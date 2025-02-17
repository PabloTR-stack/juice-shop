#!groovy

import groovy.json.JsonSlurperClassic
import java.text.SimpleDateFormat
import java.time.LocalDateTime

pipeline {
  agent { 
    kubernetes {
       yaml '''
    apiVersion: v1
    kind: Pod
    metadata:
        name: jenkins-pl-pod
        labels:
            app: jenkins-pl-pod
    spec:
        containers:
        - name: docker
          image: showcasepreprodacr.azurecr.io/docker:27.5.2-dind@sha256:3fea59d9ba248f52f0210259cc4c0849d99bce0824345b8945247d964fac9c6c
          securityContext:
            privileged: true
          ports:
          - name: dvwa
            containerPort: 4280
          - name: sock
            containerPort: 2376
        - name: dc
          image: showcasepreprodacr.azurecr.io/cached_dc:latest
          command: ["sleep"]
          args: ["infinity"]
        - name: jnlp
          image: jenkins/inbound-agent:latest
        - name: zap
          image: ghcr.io/zaproxy/zaproxy:stable
          env:
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: zap
                  key: apikey
          command: ["/bin/sh", "-c", "zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=${API_KEY} -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"]
          ports:
          - name: http
            containerPort: 8080
        '''
        }
    }
    parameters {
        booleanParam(name: 'EN_CHKOUT', defaultValue: true, description: 'If enabled, runs the "Checkout" stage')
        booleanParam(name: 'EN_SQANAL', defaultValue: true, description: 'If enabled, runs the "Sonarqube Analysis" stage')
        booleanParam(name: 'EN_SQQUGA', defaultValue: true, description: 'If enabled, runs the "Sonarqube Analysis" stage')
        booleanParam(name: 'EN_DCANAL', defaultValue: true, description: 'If enabled, runs the "OWASP Dependency Check Analysis" stage')
        booleanParam(name: 'EN_BUILDS', defaultValue: true, description: 'If enabled, runs the "Build Image" stage')
        booleanParam(name: 'EN_DEPLOY', defaultValue: true, description: 'If enabled, runs the "Deploy containers" stage')
        booleanParam(name: 'EN_ZAPANA', defaultValue: true, description: 'If enabled, runs the "OWASP Zap Analysis" stage')
        booleanParam(name: 'EN_DDUPLD', defaultValue: true, description: 'If enabled, runs the "OWASP Dependency Check Analysis" stage')
        booleanParam(name: 'EN_RELEAS', defaultValue: true, description: 'If enabled, runs the "Release" stage')
    }
    stages { 
        stage('Checkout') {
            when {
                beforeAgent true
                expression {params.EN_CHKOUT}
            }
            steps{
                container('jnlp') {
                    echo 'Downloading DVWA source code...'
                    git url: "https://github.com/PabloTR-stack/juice-shop.git"
                }
            }
        }
        stage('SonarQube analysis') {
            when {
                expression {params.EN_SQANAL}
            }
            steps{
                container('jnlp') {
                    script {
                        if (!params.EN_CHKOUT) error "Launching SonarQube analysis with no source code downloaded"
                        scannerHome = tool 'reginleifScanner'// must match the name of an actual scanner installation directory on your Jenkins build agent
                    }
                    withSonarQubeEnv('sq_yggdrasil') {// If you have configured more than one global server connection, you can specify its name as configured in Jenkins
                        nodejs(nodeJSInstallationName: 'jenkinsNodeJS') {
                            withCredentials([string(credentialsId: 'SQ_TOKEN', variable: 'SQ_TOKEN'), string(credentialsId: 'SQ_URL', variable: 'SQ_URL'), string(credentialsId: 'SQU_TOKEN', variable: 'SQU_TOKEN')]) {
                            sh scannerHome + '/bin/sonar-scanner -Dsonar.projectKey=DVWA -Dsonar.sources=./ -Dsonar.host.url=' + SQ_URL + ' -Dsonar.login=' + SQ_TOKEN
                            script{
                                String report = sh(returnStdout: true, script: 'curl -s -u '+SQU_TOKEN+': '+SQ_URL+'/api/hotspots/search?projectKey=DVWA')
                                writeFile (file: "hotspot_report.json", text: report)   
                                }  
                                    archiveArtifacts artifacts: 'hotspot_report.json'   
                            }
                        }
                    }
                }
            }
        }
        stage("Quality Gate"){
            when {
                expression {params.EN_SQQUGA}
            }
            steps{
                container('jnlp') {
                    withCredentials([string(credentialsId: 'SQ_TOKEN', variable: 'SQ_TOKEN'), string(credentialsId: 'SQ_URL', variable: 'SQ_URL'), string(credentialsId: 'SQU_TOKEN', variable: 'SQU_TOKEN')]) {
                        script{
                        if (!params.EN_SQANAL) error "Launching SonarQube Quality Gate with no SonarQube analysis"
                        String qg = sh(returnStdout: true, script: 'curl -s -u '+SQU_TOKEN+': '+SQ_URL+'/api/qualitygates/project_status?projectKey=DVWA')
                        String status = new JsonSlurperClassic().parseText(qg).projectStatus.status
                        for (i = 0 ; status != 'OK' && i < 6 ; i++) {
                            qg = sh(returnStdout: true, script: 'curl -s -u '+SQU_TOKEN+': '+SQ_URL+'/api/qualitygates/project_status?projectKey=DVWA')
                            status = new JsonSlurperClassic().parseText(qg).projectStatus.status
                            sleep 10
                            }
                        }
                    }
                }
            }
        }
        stage('OWASP Dependency-Check Vulnerabilities') {
            when {
                expression {params.EN_DCANAL}
            }
            steps{
                container('dc') {
                    script{
                        if (!params.EN_CHKOUT) error "Launching Depency Check analysis with no source code downloaded"
                    }
                    sh 'npm install'
                    sh 'npm install --package-lock'
                    sh 'dependency-check.sh \
                        --scan . \
                        -f XML \
                        --noupdate \
                        --exclude "**/*.zip"'  
                    archiveArtifacts artifacts: 'dependency-check-report.xml'
                }
            }
        } 
        stage("Build image"){
            when {
                expression {params.EN_BUILDS}
            }
            steps{
                container('docker') {
                    sh 'docker build -f Dockerfile -t jshop .'
                }
            }
        }
        stage("Deploy containers"){
            when {
                expression {params.EN_DEPLOY}
            }
            steps{
                container('docker') {
                    script{
                    if(params.EN_BUILDS) sh 'docker run --rm -d -p 3000:3000 jshop'
                    else                 sh 'docker run --rm -d -p 3000:3000 bkimminich/juice-shop'
                    }
                }
            }
        }
        
        stage("OWASP ZAP analysis"){
            when {
                expression {params.EN_ZAPANA}
            }
            steps{
                container('jnlp') {
                    withCredentials([string(credentialsId: 'ZAP_TOKEN', variable: 'ZAP_TOKEN')]) {
                        script{
                        //define URLs
                        String zap_url = "http://jenkins-pl-pod-service.reginleif.svc.cluster.local:8080"
                        String target_url = "http://jenkins-pl-pod-service.reginleif.svc.cluster.local:3000"
                        Boolean  alive = false
                        //wait for juice shop to be alive
                        while(!alive){
                            sleep 10
                            try {
                                sh 'curl '+target_url
                                alive = true
                            } catch (err) {
                                alive = false
                            }
                        }
                        //start passive scan
                        String spider_r = httpRequest zap_url+'/JSON/spider/action/scan/?apikey='+ZAP_TOKEN+'&url='+target_url+'&contextName=&recurse='
                        String scan_id = new JsonSlurperClassic().parseText(spider_r.content).scan
                        //wait for the passive scan to finish
                        String status_r,status_j
                        Integer i = 0
                        while(i < 100){
                            sleep 10
                            status_r = null
                            status_j = null
                            status_r = httpRequest url: zap_url+'/JSON/spider/view/status/?apikey='+ZAP_TOKEN+'&scanId='+scan_id ,quiet:true
                            status_j = new JsonSlurperClassic().parseText(status_r.content)
                            if (i != status_j.status.toInteger()) println("Progress: ${status_j.status}%")
                            i = status_j.status.toInteger()
                        }   

                        //start the active scan
                        ascan_r = httpRequest zap_url+'/JSON/ascan/action/scan/?apikey='+ZAP_TOKEN+'&url='+target_url+'&recurse=true&inScopeOnly=&scanPolicyName=&method=&postData=&contextId='
                        scan_id = null
                        scan_id = new JsonSlurperClassic().parseText(ascan_r.content).scan
                        //wait for the active scan to finish
                        i = 0
                        while(i < 100){
                            status_r = null
                            status_j = null
                            status_r = httpRequest url: zap_url+'/JSON/ascan/view/status/?apikey='+ZAP_TOKEN+'&scanId='+scan_id ,quiet:true
                            status_j = new JsonSlurperClassic().parseText(status_r.content)
                            if (i != status_j.status.toInteger()) println("Progress: ${status_j.status}%")
                            i = status_j.status.toInteger()
                            sleep 10
                        }
                        //get the active scan results

                            def date = new Date()
                            def sdf = new SimpleDateFormat("yyyy-MM-dd")
                            def end_date = sdf.format(date)
                        String reports_r = sh(returnStdout: true, script:  """curl -o - -X GET \
                            -H 'accept: */*' \
                            -H 'X-ZAP-API-Key: """+ZAP_TOKEN+"""' \
                            -F 'title=Juice Shop' \
                            -F 'scan_date=$end_date' \
                            -F 'sites=$target_url' \
                            -F 'reportFileName=jsonreport' \
                            -F 'code=$scan_id' \
                            -F 'message=DAST analysis of Jshop' \
                            $zap_url/OTHER/core/other/xmlreport/""")
                            writeFile (file: "zap_report.xml", text: reports_r)  
                    }
                    archiveArtifacts artifacts: 'zap_report.xml'
                    }
                }
            }
        }
        stage('DefectDojoPublisher') {
            when {
                expression {params.EN_DDUPLD}
            }
            steps{
                container('jnlp') {
                    withCredentials([string(credentialsId: 'defectDojoAPIKEY', variable: 'API_KEY')]) {
                        script{

                            // class Test {
                            // String name
                            // Boolean reimport = false
                            // Boolean active
                            // Integer id = 0
                            // String file
                            // }

                            // Test = dc  new Test(name: 'Dependency Check Scan'   ,active: EN_DCANAL  ,file:'@hotspot_report.json;type=application/json')
                            // Test = zap new Test(name: 'ZAP Scan'                ,active: EN_ZAPANA  ,file:'@zap_report.xml;type=application/xml')
                            // Test = sq  new Test(name: 'SonarQube Scan'          ,active: EN_SQANAL  ,file:'@dependency-check-report.xml;type=application/xml')

                            def date = new Date()
                            def sdf = new SimpleDateFormat("yyyy-MM-dd")
                            Integer product_id = 95
                            def end_date = sdf.format(date)
                            String dd_URL = "http://defectdojo-django.s-dm.svc.cluster.local:80"
                            Integer engagement_id = 290
                            //Comprobamos los tests que ya estén subidos al engagement
                            String test_r = sh(returnStdout: true, script:  """curl \
                            -H 'Content-Type: application/json' \
                            -H 'Authorization: Token """+API_KEY+"""' \
                            $dd_URL/api/v2/tests/?engagement=$engagement_id""")
                            def test_list = new JsonSlurperClassic().parseText(test_r).results

                            Boolean zap = false 
                            Boolean sq = false 
                            Boolean dc = false
                            Integer zap_id = 0
                            Integer sq_id = 0
                            Integer dc_id = 0

                            for (test in test_list){
                            sh 'echo "'+test+'"'
                                switch(test.scan_type){
                                    case "Dependency Check Scan":
                                        dc = true
                                        dc_id = test.id
                                        break
                                    case "ZAP Scan":
                                        zap = true
                                        zap_id = test.id
                                        break
                                    case "SonarQube Scan":
                                        sq = true
                                        sq_id = test.id
                                        break
                                    default:
                                        error "Undefined analysis $test.scan_type at engagement $engagement_id"
                                        break
                                }
                            }


                            // Análisis ZAP 
                            if(params.EN_ZAPANA) {
                                String zap_url = zap ? "$dd_URL/api/v2/reimport-scan/" : "$dd_URL/api/v2/import-scan/"
                                String zap_body = zap ? """\
                                -F 'file=@zap_report.xml;type=application/xml' \
                                -F 'scan_type=ZAP Scan' \
                                -F 'test=$zap_id'
                                """ : """\
                                -F 'engagement=$engagement_id' \
                                -F 'scan_date=$end_date' \
                                -F 'engagement_end_date=$end_date' \
                                -F 'file=@zap_report.xml;type=application/xml' \
                                -F 'scan_type=ZAP Scan' \
                                """
                                sh  """curl -o - -X POST $zap_url\
                                -H 'accept: application/json' \
                                -H 'Content-Type: multipart/form-data' \
                                -H 'Authorization: Token """+API_KEY+"""' \
                                $zap_body """
                            }

                            //Análisis SQ
                            if (params.EN_SQANAL) {
                                println(sq)
                                String sq_url = sq ? "$dd_URL/api/v2/reimport-scan/" : "$dd_URL/api/v2/import-scan/"
                                String sq_body = sq ? """\
                                -F 'file=@hotspot_report.json;type=application/json' \
                                -F 'scan_type=SonarQube Scan' \
                                -F 'test=$sq_id'
                                """ : """\
                                -F 'engagement=$engagement_id' \
                                -F 'scan_date=$end_date' \
                                -F 'engagement_end_date=$end_date' \
                                -F 'file=@hotspot_report.json;type=application/json' \
                                -F 'scan_type=SonarQube Scan' \
                                """
                                sh """curl -o - -X POST $sq_url\
                                -H 'accept: application/json' \
                                -H 'Content-Type: multipart/form-data' \
                                -H 'Authorization: Token """+API_KEY+"""' \
                                $sq_body """
                            }

                            //Análisis DC
                            if(params.EN_DCANAL) {
                                String dc_url = dc ? "$dd_URL/api/v2/reimport-scan/" : "$dd_URL/api/v2/import-scan/"
                                String dc_body = dc ? """\
                                -F 'file=@dependency-check-report.xml;type=application/xml' \
                                -F 'scan_type=Dependency Check Scan' \
                                -F 'test=$dc_id'
                                """ : """\
                                -F 'engagement=$engagement_id' \
                                -F 'scan_date=$end_date' \
                                -F 'engagement_end_date=$end_date' \
                                -F 'file=@dependency-check-report.xml;type=application/xml' \
                                -F 'scan_type=Dependency Check Scan' \
                                """
                                sh """curl -o - -X POST $dc_url\
                                -H 'accept: application/json' \
                                -H 'Content-Type: multipart/form-data' \
                                -H 'Authorization: Token """+API_KEY+"""' \
                                $dc_body """
                            }
                        }
                    }
                }
            }
        }
        stage('Release') {
            when {
                expression {params.EN_RELEAS}
            }
            steps{
                container('jnlp') {
                    sh 'echo release'
                }
            }
        }
    }
}