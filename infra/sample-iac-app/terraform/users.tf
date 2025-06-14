resource "aws_iam_user" "alice_analyst_test" {
  name = "alice-analyst-test"
  path = "/"
}

resource "aws_iam_user" "bob_dev_test" {
  name = "bob-dev-test"
  path = "/"
}

resource "aws_iam_user" "charlie_admin_test" {
  name = "charlie-admin-test"
  path = "/"
}

resource "aws_iam_user" "dave_observer_test" {
  name = "dave-observer-test"
  path = "/"
}