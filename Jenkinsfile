pipeline {
  agent any
  stages {
    stage('Pull Source Code from GitHub') {
      steps {
        git branch: 'main',
          credentialsId: 'git-credentials',
          url: 'https://github.com/anyaking922/Project01_petAdoption.git'
      }
    }
    stage('Code Analysis') {
      steps {
        withSonarQubeEnv('sonarQube') {
          sh "mvn sonar:sonar"
        }
      }
    }
    stage('Build Code') {
      steps {
        sh 'mvn -B -DskipTests clean package'
      }
    }
    stage('Send Artifacts') {
      steps {
        sshagent(['ansible-prv-key']) {
          sh 'scp -o StrictHostKeyChecking=no /var/lib/jenkins/workspace/pac-project/target/spring-petclinic-2.4.2.war ec2-user@52.214.175.111:/home/ubuntu/Docker'
        }
      }
    }
    stage('Deploy Application') {
      steps {
        sshagent(['ansible-prv-key']) {
          sh 'ssh -o strictHostKeyChecking=no ec2-user@52.214.175.111 "cd /home/ubuntu/Ansible && ansible-playbook playbook-dockerimage.yaml && ansible-playbook playbook-container.yaml && ansible-playbook playbook-newrelic.yaml"'
        }
      }
    }
  }
}
