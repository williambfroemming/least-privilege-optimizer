def get_mock_detailed_findings():
    """Mock findings for multiple users showing they all have unused permissions"""
    return [
        {
            'id': 'unused-alice-permissions-001',
            'resource_arn': 'arn:aws:iam::904610147891:user/alice-analyst-test',
            'finding_type': 'UNUSED_ACCESS',
            'unused_actions': [
                's3:PutObject',
                's3:DeleteObject', 
                'athena:CreateDataCatalog',
                'athena:DeleteWorkGroup',
                'glue:*',
                'dynamodb:Scan',
                'iam:List*',
                'iam:Get*',
                'lambda:InvokeFunction',
                'sts:AssumeRole'
            ],
            'detailed_finding': {}
        },
        {
            'id': 'unused-bob-permissions-002',
            'resource_arn': 'arn:aws:iam::904610147891:user/bob-dev-test',
            'finding_type': 'UNUSED_ACCESS',
            'unused_actions': [
                'lambda:CreateFunction',
                'lambda:DeleteFunction',
                'lambda:UpdateFunctionCode',
                's3:DeleteObject',
                's3:PutBucketPolicy',
                'iam:GetRole',
                'iam:ListRoles',
                'logs:PutLogEvents'
            ],
            'detailed_finding': {}
        },
        {
            'id': 'unused-dave-permissions-003',
            'resource_arn': 'arn:aws:iam::904610147891:user/dave-observer-test',
            'finding_type': 'UNUSED_ACCESS',
            'unused_actions': [
                'glue:GetTables',
                'cloudwatch:GetMetricData'
            ],
            'detailed_finding': {}
        }
    ]