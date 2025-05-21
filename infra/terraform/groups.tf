resource "aws_iam_group" "administrators" {
  name = "Administrators"
  path = "/"
}

resource "aws_iam_group_policy_attachment" "administrators_policy" {
  group      = aws_iam_group.administrators.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_group_membership" "admin_bfroemming" {
  user   = aws_iam_user.billfroemming_admin.name
  groups = [aws_iam_group.administrators.name]
}

resource "aws_iam_user_group_membership" "admin_dkocen" {
  user   = aws_iam_user.davidkocen_admin.name
  groups = [aws_iam_group.administrators.name]
}

resource "aws_iam_user_group_membership" "admin_ajoshi" {
  user   = aws_iam_user.aishjoshi_admin.name
  groups = [aws_iam_group.administrators.name]
}

resource "aws_iam_user_group_membership" "admin_mneith" {
  user   = aws_iam_user.mattneith_admin.name
  groups = [aws_iam_group.administrators.name]
}