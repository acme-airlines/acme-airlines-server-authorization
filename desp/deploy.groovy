pipeline {
  agent { label 'ubuntu-latest' }
  
  triggers {
    githubPush()
  }
  
  environment {
    // Credenciales de GitHub
    GITHUB_TOKEN    = credentials('github-token')
    GITHUB_USERNAME = credentials('github-username')
    // Repositorio en formato "owner/repo" sin URL ni extensión .git
    GITHUB_REPO     = "acme-airlines/acme-airlines-commons"
    
    // Parámetros para Docker
    DOCKER_IMAGE    = "mariafernanda2798/acme-airlines-authorization:latest"
    
    // Parámetros para DigitalOcean Kubernetes
    DO_K8S_DEPLOYMENT = "acme-airlines-authorization-deployment"
    DO_K8S_NAMESPACE  = "default" // Ajusta si usas otro namespace
  }
  
  tools {
    jdk 'JDK17'         // Configuración de JDK 17 en Jenkins
    maven 'Maven3'      // Configuración de Maven en Jenkins
  }
  
  stages {
    stage('Checkout Code') {
      steps {
        checkout scm
      }
    }
    
    stage('Set up Maven Settings') {
      steps {
        sh '''
          mkdir -p ~/.m2
          cat > ~/.m2/settings.xml <<EOF
          <settings>
            <servers>
              <server>
                <id>github-commons</id>
                <username>${GITHUB_USERNAME}</username>
                <password>${GITHUB_TOKEN}</password>
              </server>
              <server>
                <id>github-seguridad</id>
                <username>${GITHUB_USERNAME}</username>
                <password>${GITHUB_TOKEN}</password>
              </server>
            </servers>
          </settings>
EOF
        '''
      }
    }
    
    stage('Compile Project') {
      steps {
        sh 'mvn clean package'
      }
    }
    
    stage('Docker Build and Push') {
      steps {
        // Se utilizan las credenciales de Docker Hub (asegúrate de tener el credential con ID 'docker-hub')
        withCredentials([usernamePassword(credentialsId: 'docker-hub', usernameVariable: 'DOCKER_USERNAME', passwordVariable: 'DOCKER_PASSWORD')]) {
          sh '''
            echo "Logging into Docker Hub..."
            docker login -u "$DOCKER_USERNAME" -p "$DOCKER_PASSWORD"
            echo "Building Docker image..."
            docker build -t ${DOCKER_IMAGE} .
            echo "Pushing Docker image..."
            docker push ${DOCKER_IMAGE}
          '''
        }
      }
    }
    
    stage('Deploy to DigitalOcean Kubernetes') {
      steps {
        // Se usa el credential de tipo file para el kubeconfig de DO Kubernetes (ID: do-kubeconfig)
        withCredentials([file(credentialsId: 'do-kubeconfig', variable: 'KUBECONFIG')]) {
          sh '''
            echo "Deploying to DigitalOcean Kubernetes..."
            # Actualizar la imagen del deployment; se asume que el nombre del container coincide con el del deployment
            kubectl set image deployment/${DO_K8S_DEPLOYMENT} ${DO_K8S_DEPLOYMENT}=${DOCKER_IMAGE} -n ${DO_K8S_NAMESPACE} --record
            kubectl rollout status deployment/${DO_K8S_DEPLOYMENT} -n ${DO_K8S_NAMESPACE}
          '''
        }
      }
    }
  }
}
