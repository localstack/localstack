#!/bin/bash

# config

VERSION=1.0-SNAPSHOT
ARTIFACT=localstack-utils
GROUP=com.atlassian
LOCAL_REPO=target/m2_repo

# package artifacts via Maven

(
cd localstack/ext/java
mvn clean package

rm -rf $LOCAL_REPO/com/atlassian

mvn org.apache.maven.plugins:maven-install-plugin:2.5.2:install-file -Dfile=target/original-$ARTIFACT-$VERSION.jar \
	-DgroupId=$GROUP -DartifactId=$ARTIFACT -Dversion=$VERSION -Dpackaging=jar -DlocalRepositoryPath=$LOCAL_REPO \
	-DcreateChecksum=true
)

# copy artifacts to ./release folder

mkdir -p release
cp -r localstack/ext/java/$LOCAL_REPO/* release/
for p in release/com/atlassian/$ARTIFACT/ release/com/atlassian/$ARTIFACT/$VERSION; do
	(
		cd $p
		mv maven-metadata-local.xml maven-metadata.xml
		mv maven-metadata-local.xml.md5 maven-metadata.xml.md5
		mv maven-metadata-local.xml.sha1 maven-metadata.xml.sha1
	)
done
