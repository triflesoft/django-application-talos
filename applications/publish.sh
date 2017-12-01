#!/bin/bash

rm -r build dist *.egg-info || echo 0 >> /dev/null

./setup.py egg_info bdist_wheel

twine upload dist/*
