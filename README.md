# DefenceStrategyTestbed

The setup consist of: 
* honeypots
* central logging database
* framework scripts

## Honeypots

We use the cowrie honeypot https://github.com/micheloosterhof/cowrie, which is opensource. Setup the logging on the honeypots to use the MySQL database on the gateway.

## Central logging database

Install the MySQL database on the gateway, create database named "cowrie" and init the database as decribed in https://github.com/micheloosterhof/cowrie/blob/master/doc/sql/mysql.sql.

## Framework scripts

To run the testbed, just copy the scripts to the gateway. To start an experiment, run `python start.py <path_to_your_strategy_implementation>`. To end the experiment, run `python stop.py`. The experiment will be also evaluated, and the results will be stored in `logs/<experiment_start_data/results>`
