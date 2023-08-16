sync_out IP:
	rsync -arv --exclude='target' --exclude='params' --exclude='build' --exclude='node_modules'  ./* ubuntu@{{IP}}:~/banshee

sync_in IP:
	rsync -arv --exclude='target' --exclude='params' --exclude='build' --exclude='node_modules' ubuntu@{{IP}}:~/banshee/* .
