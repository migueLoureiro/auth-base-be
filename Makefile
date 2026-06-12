zip:
	rm ./../auth-base-be.zip
	zip -r auth-base-be.zip . -x ".git/*" -x "./data/*" -x "./vendor/*" -x ./.env -x ./go.sum 
	cp ./auth-base-be.zip ../
