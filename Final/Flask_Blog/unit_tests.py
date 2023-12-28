"""Set up the unit tests for the FlaskNews app"""
import unittest
from flasknews import app, db  

class FlaskNewsTestCase(unittest.TestCase):

    def setUp(self):
        """Set up the test environment"""
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()

        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        db.create_all()

    def tearDown(self):
        """Tear down the test environment"""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_home_page(self):
        """Test the home page"""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Home', str(response.data))

    def test_api_newsfeed(self):
        """Test the API newsfeed route"""
        response = self.app.get('/api/newsfeed')
        self.assertEqual(response.status_code, 200)
        self.assertIn('application/json', response.content_type)

    def test_newsfeed_page(self):
        """Test the newsfeed page"""
        response = self.app.get('/newsfeed')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Newsfeed', str(response.data))

    def test_register_route(self):
        """Test the /register route redirection to Auth0"""
        response = self.app.get('/register')
        self.assertEqual(response.status_code, 302)  # Redirect status

    def test_login_route(self):
        """Test the /login route redirection to Auth0"""
        response = self.app.get('/login')
        self.assertEqual(response.status_code, 302)  # Redirect status

    def test_logout_route(self):
        """Test the /logout route redirection to Auth0"""
        response = self.app.get('/logout')
        self.assertEqual(response.status_code, 302)  # Redirect status

    def test_admin_dashboard_access(self):
        """Test the /admin route without being the admin"""
        response = self.app.get('/admin')
        self.assertEqual(response.status_code, 302)  # Redirect status or 403 Forbidden

    def test_like_post_without_login(self):
        """Test liking a post without being logged in"""
        response = self.app.post('/like_post/1')  # Assuming a post with id 1 exists
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_dislike_post_without_login(self):
        """Test disliking a post without being logged in"""
        response = self.app.post('/dislike_post/1')  # Assuming a post with id 1 exists
        self.assertEqual(response.status_code, 302)  # Redirect to login

if __name__ == '__main__':
    unittest.main()
