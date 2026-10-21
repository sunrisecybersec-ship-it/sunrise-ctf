"""Smoke tests for the Sunrise CTF platform. Requires Flask: python -m unittest -v."""
import os, sys, tempfile, unittest, importlib, re, json
from pathlib import Path
ROOT=Path(__file__).resolve().parent

class ExamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        os.environ.update(SECRET_KEY='test-secret-not-for-production',ADMIN_PASSWORD='TestAdminPass-123',DB_PATH=str(Path(cls.tmp.name)/'test.db'),LEVEL='level1',PORT='8001',DURATION_MINUTES='60')
        sys.path.insert(0,str(ROOT)); cls.mod=importlib.import_module('app')
        salt='11'*16
        with cls.mod.db() as con:
            con.execute('INSERT INTO candidates(candidate_id,name,pin_salt,pin_hash,created_at) VALUES(?,?,?,?,?)',('TEST-001','Test Candidate',salt,cls.mod.pin_hash('TestPIN-123',salt),cls.mod.iso(cls.mod.utcnow())))
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def setUp(self):
        self.client=self.mod.app.test_client(); r=self.client.get('/'); self.assertEqual(r.status_code,200)
        m=re.search(r'const csrf=(.*?);',r.get_data(as_text=True)); self.csrf=json.loads(m.group(1))
    def login(self):
        r=self.client.post('/api/login',json={'candidate_id':'TEST-001','pin':'TestPIN-123'},headers={'X-CSRF-Token':self.csrf}); self.assertEqual(r.status_code,200)
    def current_csrf(self):
        with self.client.session_transaction() as s: return s['csrf']
    def test_seed_questions_and_no_answer_leak(self):
        self.login(); r=self.client.get('/api/challenges'); self.assertEqual(r.status_code,200); self.assertEqual(r.json['total'],30)
        q=self.client.get('/api/challenge/1'); self.assertEqual(q.status_code,200); self.assertNotIn('answer',q.json); self.assertNotIn('flag',q.json)
    def test_flag_validation_awards_once(self):
        self.login(); self.client.get('/api/challenges'); csrf=self.current_csrf()
        wrong=self.client.post('/api/submit',json={'id':1,'answer':'SUNRISE{wrong}'},headers={'X-CSRF-Token':csrf}); self.assertFalse(wrong.json['correct'])
        q=self.mod.get_question(1); answer=json.loads(q['answer_json'])
        good=self.client.post('/api/submit',json={'id':1,'answer':answer},headers={'X-CSRF-Token':csrf}); self.assertTrue(good.json['correct'])
        self.client.post('/api/submit',json={'id':1,'answer':answer},headers={'X-CSRF-Token':csrf})
        with self.mod.db() as con:
            n=con.execute("SELECT COUNT(*) n FROM solves WHERE candidate_id='TEST-001' AND level='level1' AND challenge_id=1").fetchone()['n']
        self.assertEqual(n,1)
    def test_answer_type_validation(self):
        self.assertTrue(self.mod.answers_match({'qtype':'single_choice','answer_json':'"B"'},'B'))
        self.assertFalse(self.mod.answers_match({'qtype':'single_choice','answer_json':'"B"'},'A'))
        self.assertTrue(self.mod.answers_match({'qtype':'multiple_choice','answer_json':'["A","C"]'},['C','A']))
        self.assertFalse(self.mod.answers_match({'qtype':'multiple_choice','answer_json':'["A","C"]'},['A']))
        self.assertTrue(self.mod.answers_match({'qtype':'short_text','answer_json':'["SQL injection","sqli"]'},' Sqli '))
        self.assertTrue(self.mod.answers_match({'qtype':'true_false','answer_json':'"true"'},'true'))
    def test_admin_requires_login(self):
        r=self.client.get('/admin/questions'); self.assertIn(r.status_code,(302,401))

    def test_super_admin_login_and_role_management_page(self):
        client=self.mod.app.test_client()
        r=client.get('/admin/login'); self.assertEqual(r.status_code,200)
        body=r.get_data(as_text=True)
        csrf=re.search(r'name="csrf" value="([^"]+)"',body).group(1)
        r=client.post('/admin/login',data={'username':'admin','password':'TestAdminPass-123','csrf':csrf},follow_redirects=True)
        self.assertEqual(r.status_code,200)
        self.assertIn('Staff Dashboard',r.get_data(as_text=True))
        r=client.get('/admin/users')
        self.assertEqual(r.status_code,200)
        text=r.get_data(as_text=True)
        self.assertIn('Super Admin',text); self.assertIn('Exam Admin',text); self.assertIn('Instructor',text); self.assertIn('Student',text)

    def test_instructor_cannot_manage_questions(self):
        salt='22'*16
        with self.mod.db() as con:
            con.execute('INSERT OR IGNORE INTO staff_users(username,full_name,role,password_salt,password_hash,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
                ('instructor1','Test Instructor','instructor',salt,self.mod.password_hash('InstructorPass-123',salt),1,self.mod.iso(self.mod.utcnow()),self.mod.iso(self.mod.utcnow())))
        client=self.mod.app.test_client(); r=client.get('/admin/login')
        csrf=re.search(r'name="csrf" value="([^"]+)"',r.get_data(as_text=True)).group(1)
        r=client.post('/admin/login',data={'username':'instructor1','password':'InstructorPass-123','csrf':csrf})
        self.assertIn(r.status_code,(302,303))
        r=client.get('/admin/questions')
        self.assertEqual(r.status_code,403)
        self.assertEqual(client.get('/admin/export.csv').status_code,200)

    def test_seed_data(self):
        for level in ('level1','level2'):
            data=json.loads((ROOT/f'challenges_{level}.json').read_text()); self.assertEqual(len(data),30)

if __name__=='__main__': unittest.main(verbosity=2)
