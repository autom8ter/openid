version := 0.0.1
.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Makefile Commands:"
	@echo "----------------------------------------------------------------"
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
	@echo "----------------------------------------------------------------"

version: ## iterate sem-ver
	bumpversion patch --allow-dirty

tag: ## tag sem-ver
	git tag v$(version)