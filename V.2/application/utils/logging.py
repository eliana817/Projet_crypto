import os
import sys
import logging
import shutil
from datetime import datetime, timedelta
import pytz
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

def setup_logging(app):
    """
    Configure logging for the Flask application with date-based directory structure
    and retention policy using Vancouver timezone.
    """
    # Create formatter with Vancouver timezone
    paris_tz = pytz.timezone('Europe/Paris')
    
    class ParisFormatter(logging.Formatter):
        def converter(self, timestamp):
            dt = datetime.fromtimestamp(timestamp)
            return paris_tz.localize(dt)
        
        def formatTime(self, record, datefmt=None):
            dt = self.converter(record.created)
            if datefmt:
                return dt.strftime(datefmt)
            return dt.strftime('%Y-%m-%d %H:%M:%S %Z')

    formatter = ParisFormatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )

    # Determine base log path based on environment
    if app.config['FLASK_ENV'] == 'development':
        base_log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'log')
    else:
        base_log_path = '/var/www/log'

    # Get current date in Paris timezone
    current_date = datetime.now(paris_tz)
    
    # Create YYYYMM folder structure
    month_folder = current_date.strftime('%Y%m')
    log_dir = os.path.join(base_log_path, month_folder)
    os.makedirs(log_dir, exist_ok=True)

    cleanup_old_logs(base_log_path, paris_tz)

def cleanup_old_logs(base_log_path, timezone):
    """
    Clean up log directories older than 6 months.
    """
    try:
        current_date = datetime.now(timezone)
        cutoff_date = current_date - timedelta(days=180)  # 6 months
        
        for dir_name in os.listdir(base_log_path):
            try:
                dir_date = datetime.strptime(dir_name, '%Y%m')
                dir_date = timezone.localize(dir_date)
                
                if dir_date < cutoff_date:
                    dir_path = os.path.join(base_log_path, dir_name)
                    shutil.rmtree(dir_path)
                    print(f"Removed old log directory: {dir_path}")
            except (ValueError, OSError) as e:
                print(f"Error processing directory {dir_name}: {str(e)}")
                continue
    except Exception as e:
        print(f"Error during cleanup: {str(e)}")