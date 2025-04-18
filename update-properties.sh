#!/bin/bash

# Default values (empty)
SB_VERSION=""
CSB_VERSION=""
CAMEL_VERSION=""
CXF_VERSION=""
CAMEL_COMMUNITY_VERSION=""
JKUBE_VERSION=""

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -sb)
      SB_VERSION="$2"
      shift 2
      ;;
    -csb)
      CSB_VERSION="$2"
      shift 2
      ;;
    -c)
      CAMEL_VERSION="$2"
      shift 2
      ;;
    -cxf)
      CXF_VERSION="$2"
      shift 2
      ;;
    -cc)
      CAMEL_COMMUNITY_VERSION="$2"
      shift 2
      ;;
    -j)
      JKUBE_VERSION="$2"
      shift 2
      ;;
    *)
      echo "Unknown parameter: $1"
      exit 1
      ;;
  esac
done

# Prompt for any missing values
if [ -z "$SB_VERSION" ]; then
  read -p "Enter the Spring Boot version (ex. 3.4.4): " SB_VERSION
fi

if [ -z "$CSB_VERSION" ]; then
  read -p "Enter the Camel Spring Boot version (ex. 4.10.3.redhat-00001): " CSB_VERSION
fi

if [ -z "$CAMEL_VERSION" ]; then
  read -p "Enter the Camel version (ex. 4.10.3.redhat-00001): " CAMEL_VERSION
fi

if [ -z "$CXF_VERSION" ]; then
  read -p "Enter the CXF version (ex. 4.1.1.rbac-redhat-00001): " CXF_VERSION
fi

if [ -z "$CAMEL_COMMUNITY_VERSION" ]; then
  read -p "Enter the Camel Community version (ex. 4.10.3): " CAMEL_COMMUNITY_VERSION
fi

if [ -z "$JKUBE_VERSION" ]; then
  read -p "Enter the JKube (Openshift Maven Plugin) version (ex. 1.18.1.redhat-00014): " JKUBE_VERSION
fi

PROPERTIES="hapi-version,guava-version,exec-maven-plugin-version,jolokia-version,metrics-version,lombok-mapstruct-binding.version,mapstruct-version,activemq-version,testcontainers-version,javafaker-version,apicurio-version,avro.maven.plugin-version,prometheus-version,reactor-version,build-helper-maven-plugin-version,maven-resources-plugin-version,awaitility-version"
echo "Automatically updating the following properties $PROPERTIES"
mvn versions:update-property -Dproperty=$PROPERTIES -DgenerateBackupPoms=false -DallowMajorUpdates=false -maven.version.ignore='(?i).*-(alpha|beta|m|rc)([-.]?\d+)?'

echo "Spring Boot Version: $SB_VERSION"
echo "CSB Version: $CSB_VERSION"
echo "Camel Version: $CAMEL_VERSION"
echo "CXF Version: $CXF_VERSION"
echo "Camel Community Version: $CAMEL_COMMUNITY_VERSION"
echo "JKube Version: $JKUBE_VERSION"
mvn versions:set-property -Dproperty=camel-version -DnewVersion=$CAMEL_VERSION -DgenerateBackupPoms=false
mvn versions:set-property -Dproperty=camel-spring-boot-version -DnewVersion=$CSB_VERSION -DgenerateBackupPoms=false
mvn versions:set-property -Dproperty=camel-community-version -DnewVersion=$CAMEL_COMMUNITY_VERSION -DgenerateBackupPoms=false
mvn versions:set-property -Dproperty=spring-boot-version -DnewVersion=$SB_VERSION -DgenerateBackupPoms=false
mvn versions:set-property -Dproperty=cxf-version -DnewVersion=$CXF_VERSION -DgenerateBackupPoms=false
mvn versions:set-property -Dproperty=jkube-maven-plugin-version -DnewVersion=$JKUBE_VERSION -DgenerateBackupPoms=false -DprofileId=openshift