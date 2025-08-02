ENV=$1

if [ "$ENV" != "dev" ] && [ "$ENV" != "prod" ]; then
  echo "Usage: ./deploy.sh [dev|prod]"
  exit 1
fi

# Source environment variables based on environment
if [ "$ENV" == "dev" ]; then
  echo "Loading development environment variables..."
  source .env.dev
else
  echo "Loading production environment variables..."
  source .env.prod
fi

# Docker login
sudo docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD

echo "Building Docker image with tag: demo-server-$ENV-$VERSION"
sudo docker build \
  --build-arg NODE_ENV=$NODE_ENV \
  -t $CI_REGISTRY:demo-server-$ENV-$VERSION \
  .

echo "Pushing Docker image to Docker Hub..."

if [ "$ENV" == "dev" ];then
  sudo docker push $CI_REGISTRY:demo-server-dev-$VERSION
else
  sudo docker push $CI_REGISTRY:demo-server-prod-$VERSION
fi



