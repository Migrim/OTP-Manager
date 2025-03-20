import os
import logging
from datetime import datetime

log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

today = datetime.now().strftime('%Y-%m-%d')
daily_log_dir = os.path.join(log_dir, today)
if not os.path.exists(daily_log_dir):
    os.makedirs(daily_log_dir)

# Main logger
log_file = os.path.join(daily_log_dir, 'main.log')
log_format = '%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s'
formatter = logging.Formatter(log_format)

my_logger = logging.getLogger('Admin')
my_logger.setLevel(logging.INFO)

handler = logging.FileHandler(log_file)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)

my_logger.addHandler(handler)

# Database logger
db_log_file = os.path.join(daily_log_dir, 'database.log')
db_formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s')

db_logger = logging.getLogger('Database_logger')
db_logger.setLevel(logging.INFO)

db_handler = logging.FileHandler(db_log_file)
db_handler.setLevel(logging.INFO)
db_handler.setFormatter(db_formatter)

db_logger.addHandler(db_handler)

if os.stat(log_file).st_size == 0:
    with open(log_file, 'a') as f:
        f.write('\n' + '='*80 + '\n')
        f.write(' '*30 + 'OTP-Manager' + '\n')
        f.write(' '*20 + f'Log Start Time: {datetime.now()}' + '\n')
        f.write('='*80 + '\n\n')

if os.stat(db_log_file).st_size == 0:
    with open(db_log_file, 'a') as f:
        f.write('\n' + '='*80 + '\n')
        f.write(' '*30 + 'Database Operations Log' + '\n')
        f.write(' '*20 + f'Log Start Time: {datetime.now()}' + '\n')
        f.write('='*80 + '\n\n')
