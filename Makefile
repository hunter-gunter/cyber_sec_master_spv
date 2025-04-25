

run-project-analysis:
	@echo "On donne des droit a notre script d'analyse pour s'executer ..."
	@chmod +x ./scripts/sys/docker-compose-scan-analisis.sh
	@echo "Lancement ..."
	@./scripts/sys/docker-compose-scan-analisis.sh

running-container-analisis:
	@echo "On donne des droit a notre script d'analyse pour s'executer ..."
	@chmod +x ./scripts/sys/running-container-analisys.sh
	@echo "Lancement ..."
	@./scripts/sys/running-container-analisys.sh
	

analysis: run-project-analysis running-container-analisis