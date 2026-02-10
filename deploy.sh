ENV=$1

if [ "$ENV" != "dev" ] && [ "$ENV" != "prod" ] && [ "$ENV" != "rlink" ]; then
  echo "Usage: ./deploy.sh [dev|prod|rlink]"
  exit 1
fi

# Source environment variables based on environment
if [ "$ENV" == "dev" ]; then
  echo "Loading development environment variables..."
  source .env.dev
elif [ "$ENV" == "prod" ]; then
  echo "Loading production environment variables..."
  source .env.prod
else
  echo "Loading rlink environment variables..."
  source .env.rlink
fi

# Docker login
sudo docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD

echo "Building Docker image with tag: demo-server-$ENV-$VERSION"
sudo docker build \
  --build-arg NODE_ENV=$NODE_ENV \
  --build-arg SDK_BACKEND_SECRET=$SDK_BACKEND_SECRET \
  --build-arg MEETING_PLATFORM_JWT_SECRET=$MEETING_PLATFORM_JWT_SECRET \
  --build-arg SERVER_URL=$SERVER_URL \
  --build-arg PORT=$PORT \
  -t $CI_REGISTRY:demo-server-$ENV-$VERSION \
  .

echo "Pushing Docker image to Docker Hub..."

if [ "$ENV" == "dev" ];then
  sudo docker push $CI_REGISTRY:demo-server-dev-$VERSION
elif [ "$ENV" == "prod" ]; then
  sudo docker push $CI_REGISTRY:demo-server-prod-$VERSION
else
  sudo docker push $CI_REGISTRY:demo-server-rlink-$VERSION
fi



