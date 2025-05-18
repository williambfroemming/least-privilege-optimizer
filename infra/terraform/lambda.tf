resource "aws_lambda_function" "test_function" {
  function_name = "testLambdaFunction"
  role          = "arn:aws:iam::904610147891:role/lambda-basic-execution"
  handler       = "index.handler"
  runtime       = "python3.13"
  timeout       = 15
  memory_size   = 128

    filename         = "${path.module}/../../lambda/test-function.zip"
    source_code_hash = filebase64sha256("${path.module}/../../lambda/test-function.zip")

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }
}
