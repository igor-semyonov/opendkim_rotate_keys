#!/bin/bash

. venv/bin/activate

export LINODE_API_KEY=$(cat api_key_linode)

opendkim-rotate-keys -v -D 30
