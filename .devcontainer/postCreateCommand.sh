#! /usr/bin/env bash

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env

# Install Dependencies
uv sync

# Install pre-commit hooks
uv run pre-commit install --install-hooks

# Install nmap and masscan
sudo apt-get update
sudo apt-get -y install nmap masscan
