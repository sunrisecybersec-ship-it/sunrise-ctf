"""Smoke tests: python -m unittest -v (inside the project environment)."""
import os, sys, tempfile, unittest, importlib, re, json
from pathlib import Path
ROOT=Path(__file__).resolve().parent

class ExamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        os.environ.update(SECRET_KEY='test-secret-not-for-production',ADMIN_PASSWORD='TestAdminPass-123',DB_PATH=str(Path(cls.tmp.name)/'test.db'),LEVEL='both',PORT='8000',LEVEL1_DURATION_MINUTES='60',LEVEL2_DURATION_MINUTES='120')
        sys.path.insert(0,str(ROOT)); cls.mod=importlib.import_module('app')
        with cls.mod.db() as con:
            for cid,name,pin,levels,salt in [('TEST-L1','Test Level One','TestPIN-123','level1','11'*16),('TEST-L2','Test Level Two','TestPIN-456','level2','22'*16),('TEST-BOTH','Test Both','TestPIN-789','level1,level2','33'*16)]:
                con.execute('INSERT OR REPLACE INTO candidates(candidate_id,name,pin_salt,pin_hash,created_at,active,allowed_levels) VALUES(?,?,?,?,?,?,?)',(cid,name,salt,cls.mod.pin_hash(pin,salt),cls.mod.iso(cls.mod.utcnow()),1,levels))
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def setUp(self):
        self.client=self.mod.app.test_client(); r=self.client.get('/'); self.assertEqual(r.status_code,200)
        m=re.search(r'const csrf=(.*?);',r.get_data(as_text=True)); self.csrf=json.loads(m.group(1))
    def login(self,cid='TEST-L1',pin='TestPIN-123'):
        r=self.client.post('/api/login',json={'candidate_id':cid,'pin':pin},headers={'X-CSRF-Token':self.csrf}); self.assertEqual(r.status_code,200,r.get_json()); return r
    def current_csrf(self):
        with self.client.session_transaction() as s: return s['csrf']
    def test_seed_questions_and_no_answer_leak(self):
        self.login(); r=self.client.get('/api/challenges'); self.assertEqual(r.status_code,200); self.assertGreater(r.json['total'],0); self.assertEqual(r.json['level'],'level1')
        q=self.client.get('/api/challenge/1'); self.assertEqual(q.status_code,200); self.assertNotIn('answer',q.json); self.assertNotIn('flag',q.json)
    def test_wrong_answer_saved_without_correctness_feedback_then_final_score(self):
        self.login(); data=self.client.get('/api/challenges').json; csrf=self.current_csrf()
        for q in data['questions']:
            r=self.client.post('/api/submit',json={'id':q['id'],'answer':'definitely-wrong'},headers={'X-CSRF-Token':csrf})
            self.assertEqual(r.status_code,200); self.assertNotIn('correct',r.json); self.assertNotIn('points',r.json)
        r=self.client.post('/api/final-submit',json={},headers={'X-CSRF-Token':csrf}); self.assertEqual(r.status_code,200)
        self.assertEqual(r.json['result']['score'],0); self.assertEqual(r.json['result']['passed'],0)
        page=self.client.get('/'); self.assertIn(b'FAIL',page.data); self.assertIn(b'0.0%',page.data)
    def test_level2_only_student_can_login_to_level2_on_same_app(self):
        self.login('TEST-L2','TestPIN-456')
        page=self.client.get('/'); self.assertIn(b'Level 2',page.data)
        data=self.client.get('/api/challenges').json; self.assertEqual(data['level'],'level2'); self.assertGreater(data['total'],0)
    def test_student_with_both_levels_can_choose_level(self):
        self.login('TEST-BOTH','TestPIN-789')
        page=self.client.get('/'); self.assertIn(b'Choose your exam',page.data)
        csrf=self.current_csrf()
        r=self.client.post('/select-level',data={'csrf':csrf,'level':'level2'},follow_redirects=True)
        self.assertEqual(r.status_code,200); self.assertIn(b'Level 2',r.data)
    def test_answer_type_validation(self):
        self.assertTrue(self.mod.answers_match({'qtype':'single_choice','answer_json':'"B"'},'B'))
        self.assertFalse(self.mod.answers_match({'qtype':'single_choice','answer_json':'"B"'},'A'))
        self.assertTrue(self.mod.answers_match({'qtype':'multiple_choice','answer_json':'["A","C"]'},['C','A']))
        self.assertFalse(self.mod.answers_match({'qtype':'multiple_choice','answer_json':'["A","C"]'},['A']))
        self.assertTrue(self.mod.answers_match({'qtype':'short_text','answer_json':'["SQL injection","sqli"]'},' Sqli '))
        self.assertTrue(self.mod.answers_match({'qtype':'true_false','answer_json':'"true"'},'true'))
    def test_admin_requires_login(self):
        self.assertIn(self.client.get('/admin/questions').status_code,(302,401))
    def test_question_builder_page_has_no_json_editor(self):
        client=self.mod.app.test_client(); r=client.get('/admin/login'); csrf=re.search(r'name="csrf" value="([^"]+)"',r.get_data(as_text=True)).group(1)
        client.post('/admin/login',data={'username':'admin','password':'TestAdminPass-123','csrf':csrf})
        r=client.get('/admin/questions'); self.assertEqual(r.status_code,200); text=r.get_data(as_text=True)
        self.assertIn('Add option',text); self.assertNotIn('Options JSON (MCQ only)',text)
    def test_health_endpoint(self):
        self.assertEqual(self.client.get('/healthz').status_code,200)

if __name__=='__main__': unittest.main(verbosity=2)
