pipeline{
    agent any
    environment {
        DOCKER_USER     = credentials('dockeruser')
        DOCKER_PASSWORD = credentials('dockerPwd')
    }
    stages {
        stage('BuildCode'){
            steps{

               sh 'mvn install -DskipTests=true'
            }
        }
        stage('DockerBuild'){
            steps{
                sh 'bash && docker build -t cloudhight/pipeline:1.0.11 .'
            }
        }
        stage('DockerLogin') {
            steps{
                sh 'docker login --username $DOCKER_USER --password $DOCKER_PASSWORD'
            }
        }
        stage('DockerPush') {
            steps{
                sh 'docker push cloudhight/pipeline:1.0.11'
            }
        }
        stage('Deploy') {
             steps {
               sshagent (['ansible_creds']) {
                   sh 'ssh -t -t ec2-user@10.0.3.154 -o strictHostKeyChecking=no "cd /etc/ansible && ansible-playbook MyPlaybook.yaml"'
                }
            }
        }
    }
}
