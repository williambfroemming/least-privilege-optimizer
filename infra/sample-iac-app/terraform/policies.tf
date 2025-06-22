
# MODIFIED BY LEAST PRIVILEGE OPTIMIZER - 2025-06-22 14:34:14
# Finding ID: d6d84c8d-e05c-49ae-8502-c30cad4ba761
# Resource: charlie_admin_test
# Removed unused services: a2c, a4b, access-analyzer, account, acm, acm-pca, activate, aiops, airflow, amplify, amplifybackend, amplifyuibuilder, aoss, apigateway, app-integrations, appconfig, appfabric, appflow, application-autoscaling, application-cost-profiler, application-signals, application-transformation, applicationinsights, appmesh, appmesh-preview, apprunner, appstream, appstudio, appsync, apptest, aps, arc-zonal-shift, arsenal, artifact, athena, auditmanager, autoscaling, autoscaling-plans, aws-marketplace, aws-marketplace-management, aws-portal, awsconnector, b2bi, backup, backup-gateway, backup-search, backup-storage, batch, bcm-data-exports, bcm-pricing-calculator, bedrock, billing, billingconductor, braket, budgets, bugbust, cases, cassandra, ce, chatbot, chime, cleanrooms, cleanrooms-ml, cloud9, clouddirectory, cloudformation, cloudfront, cloudfront-keyvaluestore, cloudhsm, cloudsearch, cloudshell, cloudtrail, cloudtrail-data, cloudwatch, codeartifact, codebuild, codecatalyst, codecommit, codeconnections, codedeploy, codedeploy-commands-secure, codeguru, codeguru-profiler, codeguru-reviewer, codeguru-security, codepipeline, codestar, codestar-connections, codestar-notifications, codewhisperer, cognito-identity, cognito-idp, cognito-sync, comprehend, comprehendmedical, compute-optimizer, config, connect, connect-campaigns, consoleapp, consolidatedbilling, controlcatalog, controltower, cost-optimization-hub, cur, customer-verification, databrew, dataexchange, datapipeline, datasync, datazone, dax, dbqms, deadline, deepcomposer, deepracer, detective, devicefarm, devops-guru, directconnect, discovery, dlm, dms, docdb-elastic, drs, ds, ds-data, dsql, dynamodb, ebs, ec2, ec2-instance-connect, ec2messages, ecr, ecr-public, ecs, eks, eks-auth, elasticache, elasticbeanstalk, elasticfilesystem, elasticloadbalancing, elasticmapreduce, elastictranscoder, elemental-activations, elemental-appliances-software, elemental-support-cases, elemental-support-content, emr-containers, emr-serverless, entityresolution, es, events, evidently, evs, execute-api, finspace, finspace-api, firehose, fis, fms, forecast, frauddetector, freertos, freetier, fsx, gamelift, gameliftstreams, geo, geo-maps, geo-places, geo-routes, glacier, globalaccelerator, glue, grafana, greengrass, groundstation, groundtruthlabeling, guardduty, health, healthlake, honeycode, iam, identity-sync, identitystore, identitystore-auth, imagebuilder, importexport, inspector, inspector-scan, inspector2, internetmonitor, invoicing, iot, iot-device-tester, iot1click, iotanalytics, iotdeviceadvisor, iotevents, iotfleethub, iotfleetwise, iotjobsdata, iotmanagedintegrations, iotsitewise, iottwinmaker, iotwireless, iq, iq-permission, ivs, ivschat, kafka, kafka-cluster, kafkaconnect, kendra, kendra-ranking, kinesis, kinesisanalytics, kinesisvideo, kms, lakeformation, lambda, launchwizard, lex, license-manager, license-manager-linux-subscriptions, license-manager-user-subscriptions, lightsail, logs, lookoutequipment, lookoutmetrics, lookoutvision, m2, machinelearning, macie2, managedblockchain, managedblockchain-query, mapcredits, marketplacecommerceanalytics, mechanicalturk, mediaconnect, mediaconvert, mediaimport, medialive, mediapackage, mediapackage-vod, mediapackagev2, mediastore, mediatailor, medical-imaging, memorydb, mgh, mgn, migrationhub-orchestrator, migrationhub-strategy, mobileanalytics, mobiletargeting, monitron, mpa, mq, neptune-db, neptune-graph, network-firewall, networkflowmonitor, networkmanager, networkmanager-chat, networkmonitor, nimble, notifications, notifications-contacts, oam, observabilityadmin, omics, one, opensearch, opsworks, opsworks-cm, organizations, osis, outposts, panorama, partnercentral, partnercentral-account-management, payment-cryptography, payments, pca-connector-ad, pca-connector-scep, pcs, personalize, pi, pipes, polly, pricing, private-networks, profile, proton, purchase-orders, q, qapps, qbusiness, qdeveloper, qldb, quicksight, ram, rbin, rds, rds-data, rds-db, redshift, redshift-data, redshift-serverless, refactor-spaces, rekognition, repostspace, resiliencehub, resource-explorer, resource-explorer-2, resource-groups, rhelkb, robomaker, rolesanywhere, route53, route53-recovery-cluster, route53-recovery-control-config, route53-recovery-readiness, route53domains, route53profiles, route53resolver, rum, s3, s3-object-lambda, s3-outposts, s3express, s3tables, sagemaker, sagemaker-data-science-assistant, sagemaker-geospatial, sagemaker-mlflow, savingsplans, scheduler, schemas, scn, sdb, secretsmanager, security-ir, securityhub, securitylake, serverlessrepo, servicecatalog, servicediscovery, serviceextract, servicequotas, ses, shield, signer, signin, simspaceweaver, sms, sms-voice, snow-device-management, snowball, sns, social-messaging, sqlworkbench, sqs, ssm, ssm-contacts, ssm-guiconnect, ssm-incidents, ssm-quicksetup, ssm-sap, ssmmessages, sso, sso-directory, sso-oauth, states, storagegateway, sts, support, support-console, supportapp, supportplans, supportrecommendations, sustainability, swf, synthetics, tag, tax, textract, thinclient, timestream, timestream-influxdb, tiros, tnb, transcribe, transfer, transform, translate, trustedadvisor, ts, user-subscriptions, vendor-insights, verified-access, verifiedpermissions, voiceid, vpc-lattice, vpc-lattice-svcs, vpce, waf, waf-regional, wafv2, wam, wellarchitected, wickr, wisdom, workdocs, worklink, workmail, workmailmessageflow, workspaces, workspaces-instances, workspaces-web, xray
# This modification removes 423 unused service permissions
# Based on AWS Access Analyzer findings for least privilege access
#
resource "aws_iam_user_policy" "alice_analyst_policy" {
  name = "alice-analyst-test-policy"
  user = aws_iam_user.alice_analyst_test.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "OverlyPermissiveReadAndWrite",
        Effect   = "Allow",
        Action   = [
          "*",                         # Full S3 acss
          "*",                     # All Athena actions
          "*",                       # All Glue actions (overkill for most analy)
          "cloudwatch:Get*",              # OK
          "cloudwatch:PutMetricData",     # Write perms analysts shouldn't need
          "dynamodb:Scan",                # Too broad for sensitive data
          "kms:Decrypt",                  # Dangerous without restrictions
          "iam:List*",                    # Allows recon
          "iam:Get*",                     # More recon
          "lambda:InvokeFunction",        # Could be misused
          "sts:AssumeRole"                # Very risky unless scoped tightly
        ],
        Resource = "*"
      }
    ]
  })
}


resource "aws_iam_user_policy" "bob_dev_policy" {
  name = "bob-dev-test-policy"
  user = aws_iam_user.bob_dev_test.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid: "LambdaOverreach",
        Effect: "Allow",
        Action: [
          "*"                          # Too much
        ],
        Rour "*"
      },
      {
        Sid: "S3FullBucketAcss",
        Effect: "Allow",
        Action: [
          "PutObject",
          "GetObject",
          "ListBucket",
          "DeleteObject",                  # Exssive
          "PutBucketPolicy",               # Definitely too much
          "GetBucketAcl"
        ],
        Rour [
          "arn:aws:ucb-ct-bucket",
          "arn:aws:ucb-ct-bucket/*"
        ]
      },
      {
        Sid: "IAMReconAcss",
        Effect: "Allow",
        Action: [
          "GetRole",
          "ListRol"
        ],
        Rour "*"
      },
      {
        Sid: "CloudWatchLogsAcss",
        Effect: "Allow",
        Action: [
          "DcribeLogGroups",
          "GetLogEven",
          "FilterLogEven",
          "PutLogEven"                # Not always needed
        ],
        Rour "*"
      },
      {
        Sid: "ECSAndECRAcss",
        Effect: "Allow",
        Action: [
          "ListClusters",
          "DcribeTasks",
          "GetAuthorizationToken",
          "DcribeRepositori"
        ],
        Rour "*"
      }
    ]
  })
}


resource "aws_iam_user_policy_attachment" "charlie_admin_access" {
  user       = aws_iam_user.charlie_admin_test.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_policy" "dave_observer_policy" {
  name = "dave-observer-test-policy"
  user = aws_iam_user.dave_observer_test.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "GetLogEven",
          "DcribeLogStreams",
          "DcribeLogGroups",
          "GetObject",
          "ListBucket",
          "GetMetricData",
          "GetTabl"
        ],
        Rour = "*"
      }
    ]
  })
}