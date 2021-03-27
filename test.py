try:
    from app import app
    import unittest
except Exception as e:
    print("Some Modules are missing {}!".format(e))


class APITest(unittest.TestCase):

    
    def test_app_user(self):
        tester = app.test_client(self)
        response = tester.get("/user")
        self.assertEqual(response.content_type,"application/json")


    def test_user_data(self):
        tester = app.test_client(self)
        response = tester.get("/user")
        self.assertTrue(b'Message' in response.data)


    def test_app_task(self):
        tester = app.test_client(self)
        response = tester.get("/task")
        self.assertEqual(response.content_type,"application/json")

    
    def test_task_data(self):
        tester = app.test_client(self)
        response = tester.get("/task")
        self.assertTrue(b'Message' in response.data)


if __name__ == "__main__":
    unittest.main()