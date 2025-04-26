from flask import Flask, request, jsonify, render_template, send_file
import pandas as pd
import re
import json
import os
from datetime import datetime
import numpy as np
from collections import Counter
import io

app = Flask(__name__)

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Common log patterns
LOG_PATTERNS = {
    'apache': r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+)',
    'nginx': r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+)',
    'syslog': r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<process>\S+): (?P<message>.*)',
    'windows_event': r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}) (?P<event_id>\d+) (?P<level>\w+) (?P<source>\S+) (?P<message>.*)',
    'rsvp': r'(?P<timestamp>\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+:(?P<module>[^:]+):\s+(?P<message>.*)',
    'oracle_bulkops': r'\[(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\]\s+(?P<level>\w+)\s+-\s+\[(?P<thread>[^\]]+)\]\s+(?P<class>[^:]+):\s+(?P<message>.*)'
}

def detect_log_format(log_content):
    """Detect the format of the log file"""
    for format_name, pattern in LOG_PATTERNS.items():
        if re.search(pattern, log_content[:1000]):
            return format_name, pattern
    return None, None

def parse_logs(log_content, pattern):
    """Parse logs using the detected pattern"""
    matches = re.finditer(pattern, log_content)
    parsed_logs = []
    for match in matches:
        log_entry = match.groupdict()
        # Clean up values
        for key, value in log_entry.items():
            if isinstance(value, str):
                log_entry[key] = value.strip()
        parsed_logs.append(log_entry)
    return parsed_logs

def analyze_logs(parsed_logs):
    """Analyze parsed logs for patterns and anomalies"""
    if not parsed_logs:
        return {}
    
    analysis = {
        'summary': {},
        'patterns': {},
        'anomalies': {},
        'performance': {},
        'security': {},
        'operations': {},
        'correlations': {},
        'sequences': {},
        'trends': {},
        'impact_analysis': {}
    }
    
    # Convert to DataFrame for easier analysis
    df = pd.DataFrame(parsed_logs)
    
    def convert_to_serializable(obj):
        """Convert numpy/pandas types to native Python types"""
        if isinstance(obj, (np.int64, np.int32, np.int16, np.int8)):
            return int(obj)
        elif isinstance(obj, (np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, pd.Timestamp):
            return str(obj)
        elif isinstance(obj, pd.Timedelta):
            return str(obj)
        elif isinstance(obj, dict):
            return {k: convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_to_serializable(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(convert_to_serializable(item) for item in obj)
        elif isinstance(obj, (pd.Series, pd.DataFrame)):
            return convert_to_serializable(obj.to_dict())
        return obj
    
    # Basic summary statistics
    if 'level' in df.columns:
        level_dist = df['level'].value_counts()
        analysis['summary']['level_distribution'] = convert_to_serializable(level_dist.to_dict())
        analysis['summary']['total_entries'] = int(len(df))
        analysis['summary']['unique_levels'] = int(df['level'].nunique())
    
    # Thread/Process Analysis
    if 'thread' in df.columns:
        thread_analysis = df['thread'].value_counts()
        analysis['summary']['thread_activity'] = convert_to_serializable(thread_analysis.to_dict())
        analysis['summary']['thread_metrics'] = {
            'total_threads': int(thread_analysis.count()),
            'most_active_thread': str(thread_analysis.idxmax()),
            'thread_distribution': convert_to_serializable(thread_analysis.describe().to_dict())
        }
    
    # Time-based Analysis
    if 'timestamp' in df.columns:
        try:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            time_range = {
                'start': str(df['timestamp'].min()),
                'end': str(df['timestamp'].max()),
                'duration': str(df['timestamp'].max() - df['timestamp'].min())
            }
            analysis['summary']['time_range'] = time_range
            
            # Enhanced time-based metrics
            df['minute'] = df['timestamp'].dt.floor('min')
            df['hour'] = df['timestamp'].dt.hour
            df['day'] = df['timestamp'].dt.date
            
            # Events per time period
            events_per_minute = df.groupby('minute').size()
            analysis['performance']['events_per_minute'] = {
                'mean': float(events_per_minute.mean()),
                'max': float(events_per_minute.max()),
                'min': float(events_per_minute.min()),
                'std_dev': float(events_per_minute.std())
            }
            
            # Hourly distribution
            hourly_dist = df.groupby('hour').size()
            analysis['trends']['hourly_distribution'] = {
                'distribution': convert_to_serializable(hourly_dist.to_dict()),
                'peak_hour': int(hourly_dist.idxmax()),
                'off_peak_hour': int(hourly_dist.idxmin())
            }
            
            # Detect unusual time patterns
            time_diff = df['timestamp'].diff()
            unusual_gaps = time_diff[time_diff > time_diff.mean() + 2 * time_diff.std()]
            if not unusual_gaps.empty:
                analysis['anomalies']['unusual_time_gaps'] = {
                    str(idx): {
                        'gap_duration': str(gap),
                        'context': {
                            'before': str(df.loc[idx-1, 'message']) if idx > 0 else None,
                            'after': str(df.loc[idx, 'message']) if idx < len(df) else None
                        }
                    } for idx, gap in unusual_gaps.items()
                }
        except Exception as e:
            print(f"Error in time analysis: {str(e)}")
    
    # Message Analysis
    if 'message' in df.columns:
        # Enhanced message pattern analysis
        message_patterns = df['message'].value_counts()
        analysis['patterns']['common_messages'] = {
            'top_messages': convert_to_serializable(message_patterns.head(10).to_dict()),
            'unique_messages': int(message_patterns.count()),
            'message_length_stats': {
                'mean': float(df['message'].str.len().mean()),
                'max': float(df['message'].str.len().max()),
                'min': float(df['message'].str.len().min())
            }
        }
        
        # Error and Warning Analysis
        if 'level' in df.columns:
            error_messages = df[df['level'].str.contains('ERROR|WARNING', case=False)]
            if not error_messages.empty:
                analysis['anomalies']['errors_and_warnings'] = {
                    'count': int(len(error_messages)),
                    'distribution': convert_to_serializable(error_messages['level'].value_counts().to_dict()),
                    'messages': convert_to_serializable(error_messages['message'].value_counts().head(5).to_dict()),
                    'error_rate': float(len(error_messages) / len(df)),
                    'error_trend': convert_to_serializable(error_messages.groupby('minute').size().to_dict())
                }
        
        # Security Analysis
        security_keywords = ['login', 'password', 'authentication', 'authorization', 'access', 'session']
        security_messages = df[df['message'].str.contains('|'.join(security_keywords), case=False)]
        if not security_messages.empty:
            analysis['security']['security_events'] = {
                'count': int(len(security_messages)),
                'events': convert_to_serializable(security_messages['message'].value_counts().head(5).to_dict()),
                'security_metrics': {
                    'login_attempts': int(len(security_messages[security_messages['message'].str.contains('login', case=False)])),
                    'session_events': int(len(security_messages[security_messages['message'].str.contains('session', case=False)])),
                    'access_events': int(len(security_messages[security_messages['message'].str.contains('access', case=False)]))
                }
            }
        
        # Performance Analysis
        performance_keywords = ['timeout', 'latency', 'response', 'execution', 'complete', 'duration']
        performance_messages = df[df['message'].str.contains('|'.join(performance_keywords), case=False)]
        if not performance_messages.empty:
            analysis['performance']['performance_events'] = {
                'count': int(len(performance_messages)),
                'events': convert_to_serializable(performance_messages['message'].value_counts().head(5).to_dict()),
                'performance_metrics': {
                    'timeout_events': int(len(performance_messages[performance_messages['message'].str.contains('timeout', case=False)])),
                    'execution_times': convert_to_serializable(performance_messages[performance_messages['message'].str.contains('execution', case=False)]['message'].value_counts().head(3).to_dict())
                }
            }
        
        # Operation Analysis
        operation_keywords = ['request', 'import', 'export', 'process', 'submit', 'bulk']
        operation_messages = df[df['message'].str.contains('|'.join(operation_keywords), case=False)]
        if not operation_messages.empty:
            analysis['operations']['operation_events'] = {
                'count': int(len(operation_messages)),
                'events': convert_to_serializable(operation_messages['message'].value_counts().head(5).to_dict()),
                'operation_metrics': {
                    'import_events': int(len(operation_messages[operation_messages['message'].str.contains('import', case=False)])),
                    'export_events': int(len(operation_messages[operation_messages['message'].str.contains('export', case=False)])),
                    'request_events': int(len(operation_messages[operation_messages['message'].str.contains('request', case=False)]))
                }
            }
        
        # Sequence Analysis
        if 'level' in df.columns and 'message' in df.columns:
            sequences = []
            for i in range(len(df) - 1):
                sequences.append((df.iloc[i]['level'], df.iloc[i+1]['level']))
            
            sequence_counts = pd.Series(sequences).value_counts()
            analysis['sequences']['common_sequences'] = {
                'top_sequences': convert_to_serializable(sequence_counts.head(5).to_dict()),
                'total_unique_sequences': int(sequence_counts.count())
            }
    
    # Class/Method Analysis
    if 'class' in df.columns:
        class_analysis = df['class'].value_counts()
        analysis['patterns']['top_classes'] = {
            'distribution': convert_to_serializable(class_analysis.head(10).to_dict()),
            'metrics': {
                'total_classes': int(class_analysis.count()),
                'most_active_class': str(class_analysis.idxmax()),
                'class_distribution_stats': convert_to_serializable(class_analysis.describe().to_dict())
            }
        }
    
    # Correlation Analysis
    if 'level' in df.columns and 'message' in df.columns:
        df['message_length'] = df['message'].str.len()
        level_length_corr = df.groupby('level')['message_length'].mean()
        analysis['correlations']['level_message_length'] = convert_to_serializable(level_length_corr.to_dict())
    
    # Impact Analysis
    if 'level' in df.columns and 'message' in df.columns:
        error_indices = df[df['level'].str.contains('ERROR', case=False)].index
        impact_analysis = {
            'error_impact': {
                'total_errors': int(len(error_indices)),
                'error_recovery_time': {},
                'error_cascade_effects': {}
            }
        }
        
        for idx in error_indices:
            if idx < len(df) - 1:
                next_success = df.iloc[idx+1:][df['level'].str.contains('INFO|SUCCESS', case=False)]
                if not next_success.empty:
                    recovery_time = next_success.index[0] - idx
                    impact_analysis['error_impact']['error_recovery_time'][str(idx)] = str(recovery_time)
            
            subsequent_errors = df.iloc[idx+1:idx+5][df['level'].str.contains('ERROR', case=False)]
            if not subsequent_errors.empty:
                impact_analysis['error_impact']['error_cascade_effects'][str(idx)] = {
                    'subsequent_errors': int(len(subsequent_errors)),
                    'error_messages': subsequent_errors['message'].tolist()
                }
        
        analysis['impact_analysis'] = impact_analysis
    
    return analysis

def export_logs(parsed_logs, format_type):
    """Export logs in different formats"""
    df = pd.DataFrame(parsed_logs)
    
    if format_type == 'csv':
        output = io.StringIO()
        df.to_csv(output, index=False)
        return output.getvalue()
    elif format_type == 'json':
        return df.to_json(orient='records')
    elif format_type == 'excel':
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False)
        return output.getvalue()
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        content = None
        
        # Check if file was uploaded
        if 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            content = file.read().decode('utf-8')
            
        # Check if log content was pasted
        elif 'log_content' in request.form:
            content = request.form['log_content']
            
        if not content:
            return jsonify({'error': 'No log content provided'}), 400
            
        # Detect log format
        format_name, pattern = detect_log_format(content)
        if not pattern:
            return jsonify({'error': 'Unsupported log format'}), 400
            
        # Parse logs
        parsed_logs = parse_logs(content, pattern)
        
        # Analyze logs
        analysis = analyze_logs(parsed_logs)
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = f'log_analysis_{timestamp}.json'
        with open(os.path.join(UPLOAD_FOLDER, results_file), 'w') as f:
            json.dump(analysis, f)
            
        return jsonify({
            'message': 'Analysis completed successfully',
            'format': format_name,
            'analysis': analysis
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/export', methods=['POST'])
def export():
    try:
        data = request.get_json()
        if not data or 'logs' not in data or 'format' not in data:
            return jsonify({'error': 'Invalid request format'}), 400
            
        exported_data = export_logs(data['logs'], data['format'])
        if not exported_data:
            return jsonify({'error': 'Unsupported export format'}), 400
            
        return jsonify({
            'data': exported_data,
            'format': data['format']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5005) 