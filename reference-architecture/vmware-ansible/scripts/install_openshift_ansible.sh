#! /bin/bash
#
# List of expected input args:
# - $1 is an env dir, i.e '/home/username/.../.tox/ocp3.6'
# - $2 is a tag to checkout from,
#   i.e. 'openshift-ansible-3.6.173.0.96-1' for OCP v3.6
#   See list of tags here: https://github.com/openshift/openshift-ansible/tags

OPENSHIFT_ANSIBLE_GIT_URL='git://github.com/openshift/openshift-ansible.git'
TARGET_DIR=$1/usr/share/ansible/openshift-ansible

if [[ ! -d $TARGET_DIR ]]; then
    mkdir -p $TARGET_DIR
    git clone $OPENSHIFT_ANSIBLE_GIT_URL --single-branch --branch $2 $TARGET_DIR
else
    cd $TARGET_DIR
    git fetch --all
    git reset --hard $2
fi
