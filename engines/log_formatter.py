"""
Log Formatter - Transforms logs into standardized schema
All logs that TDARE recieves must follow the exact schema structure
"""

from datetime import datetime
from typing import Dict, Any
import time


class LogFormatter:
    """Formats logs into standardized schema"""

    # Required schema fields in strict order
    SCHEMA_FIELDS = [
        #PowerShell-MainFields
        "@timestamp",
        "date",
        "SecurityProtocol",
        "CommandLine",
        "ProgressPreference",
        "Channel",
        "ProviderName",
        "NewProviderState",
        "SourceName",
        "CommandInfo",
        "EventID",
        "EventType",
        "RecordNumber",
        "EventCategory",
        "ComputerName",
        "AlertLevel",
        "CommandDescription",
        "HostApplication",
        "ScriptName",
        "HostVersion",
        "UserId",
        "DetailSequence",
        "Path",
        "URL",
        "TimeGenerated",
        "PipelineID",
        "TimeWritten",
        "Qualifiers",
        "SequenceNumber",

        # PowerShell-enriched fields
        "Script",
        "App",
        "OutFile",
        "ExecutionPolicy",
        "LocData",
        "RootRegPath",
        "GUID",
        "GUIDName",
        "BagMRU",
        "Bags",
        "Function",
        "UEFI_DB_Read",
        "CertSignature",
        "CertificateID",
        "HostIP",
        "HostName"
    ]

    @staticmethod
    def format_log(raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format a raw log entry into the standardized schema
        """

        # Extract source
        if "_source" in raw_log:
            source = raw_log["_source"]
        elif "data" in raw_log:
            source = raw_log["data"]
        else:
            source = raw_log

        formatted = {}

        # Timestamp handling
        timestamp = LogFormatter._extract_timestamp(source, raw_log)
        formatted["@timestamp"] = timestamp
        formatted["date"] = LogFormatter._extract_date(timestamp)

        # Core fields
        formatted["SecurityProtocol"] = LogFormatter._get_string_field(
            source, ["SecurityProtocol", "security_protocol", "protocol"], "N/A"
        )

        formatted["CommandLine"] = LogFormatter._get_string_field(
            source, ["CommandLine", "command_line", "command", "cmd"], "N/A"
        )

        formatted["ProgressPreference"] = LogFormatter._get_string_field(
            source, ["ProgressPreference", "progress_preference", "progress"], "N/A"
        )

        formatted["Channel"] = LogFormatter._get_string_field(
            source, ["Channel", "channel", "log_channel"], "N/A"
        )

        formatted["ProviderName"] = LogFormatter._get_string_field(
            source, ["ProviderName", "provider_name", "provider", "source"], "N/A"
        )

        formatted["NewProviderState"] = LogFormatter._get_string_field(
            source, ["NewProviderState", "new_provider_state"], "N/A"
        )

        formatted["SourceName"] = LogFormatter._get_string_field(
            source, ["SourceName", "source_name"], "N/A"
        )

        formatted["CommandInfo"] = LogFormatter._get_string_field(
            source, ["CommandInfo", "command_info", "cmd_info"], "N/A"
        )

        formatted["EventID"] = LogFormatter._get_numeric_field(
            source, ["EventID", "event_id", "EventId", "id"], 0
        )

        formatted["EventType"] = LogFormatter._get_string_field(
            source, ["EventType", "event_type", "type"], "N/A"
        )

        formatted["RecordNumber"] = LogFormatter._get_numeric_field(
            source, ["RecordNumber", "record_number"], 0
        )

        formatted["EventCategory"] = LogFormatter._get_numeric_field(
            source, ["EventCategory", "event_category"], 0
        )

        formatted["ComputerName"] = LogFormatter._get_string_field(
            source, ["ComputerName", "computer_name", "hostname", "host"], "N/A"
        )

        formatted["AlertLevel"] = LogFormatter._get_string_field(
            source, ["AlertLevel", "alert_level", "severity", "level"], "Normal"
        )

        formatted["CommandDescription"] = LogFormatter._get_string_field(
            source, ["CommandDescription", "command_description", "description"], "N/A"
        )

        formatted["HostApplication"] = LogFormatter._get_string_field(
            source, ["HostApplication", "host_application", "application"], "N/A"
        )

        formatted["ScriptName"] = LogFormatter._get_string_field(
            source, ["ScriptName", "script_name"], "N/A"
        )

        formatted["HostVersion"] = LogFormatter._get_string_field(
            source, ["HostVersion", "host_version", "version"], "N/A"
        )

        formatted["UserId"] = LogFormatter._get_string_field(
            source, ["UserId", "user_id", "user", "username"], "N/A"
        )

        formatted["DetailSequence"] = LogFormatter._get_string_field(
            source, ["DetailSequence", "detail_sequence"], "N/A"
        )

        formatted["Path"] = LogFormatter._get_string_field(
            source, ["Path", "path", "file_path"], "N/A"
        )

        formatted["URL"] = LogFormatter._get_string_field(
            source, ["URL", "url", "uri"], "N/A"
        )

        formatted["TimeGenerated"] = LogFormatter._get_string_field(
            source,
            ["TimeGenerated", "time_generated", "@timestamp", "timestamp"],
            LogFormatter._format_timestamp(timestamp)
        )

        formatted["PipelineID"] = LogFormatter._get_string_field(
            source, ["PipelineID", "pipeline_id", "pipeline"], "N/A"
        )

        formatted["Script"] = LogFormatter._get_string_field(
            source, ["Script", "script"], "N/A"
        )

        formatted["TimeWritten"] = LogFormatter._get_string_field(
            source,
            ["TimeWritten", "time_written"],
            LogFormatter._format_timestamp(timestamp)
        )

        formatted["Qualifiers"] = LogFormatter._get_numeric_field(
            source, ["Qualifiers", "qualifiers"], 0
        )

        formatted["SequenceNumber"] = LogFormatter._get_string_field(
            source, ["SequenceNumber", "sequence_number"], "N/A"
        )

        # PowerShell-specific enrichment
        formatted["App"] = LogFormatter._get_string_field(
            source, ["App", "app"], "N/A"
        )

        formatted["OutFile"] = LogFormatter._get_string_field(
            source, ["OutFile", "out_file"], "N/A"
        )

        formatted["ExecutionPolicy"] = LogFormatter._get_string_field(
            source, ["ExecutionPolicy", "execution_policy"], "N/A"
        )

        formatted["LocData"] = LogFormatter._get_string_field(
            source, ["LocData", "local_data"], "N/A"
        )

        formatted["RootRegPath"] = LogFormatter._get_string_field(
            source, ["RootRegPath", "root_reg_path"], "N/A"
        )

        formatted["GUID"] = LogFormatter._get_string_field(
            source, ["GUID", "guid"], "N/A"
        )

        formatted["GUIDName"] = LogFormatter._get_string_field(
            source, ["GUIDName", "guid_name"], "N/A"
        )

        formatted["BagMRU"] = LogFormatter._get_string_field(
            source, ["BagMRU", "bag_mru"], "N/A"
        )

        formatted["Bags"] = LogFormatter._get_string_field(
            source, ["Bags", "bags"], "N/A"
        )

        formatted["Function"] = LogFormatter._get_string_field(
            source, ["Function", "function"], "N/A"
        )

        formatted["UEFI_DB_Read"] = LogFormatter._get_string_field(
            source, ["UEFI_DB_Read", "uefi_db_read"], "False"
        )

        formatted["CertSignature"] = LogFormatter._get_string_field(
            source, ["CertSignature", "cert_signature"], "N/A"
        )

        formatted["CertificateID"] = LogFormatter._get_string_field(
            source, ["CertificateID", "certificate_id"], "N/A"
        )


        formatted["HostIP"] = LogFormatter._get_string_field(
            source, ["Host_IP", "host_ip"], "N/A"
        )


        formatted["HostName"] = LogFormatter._get_string_field(
            source, ["HostName", "hostname" , "host_name"], "N/A"
        )

        return LogFormatter._ensure_schema_order(formatted)

    # ================= Helper functions (UNCHANGED) =================

    @staticmethod
    def _extract_timestamp(source: Dict[str, Any], raw_log: Dict[str, Any]) -> str:
        timestamp = source.get("@timestamp") or source.get("timestamp") or source.get("time")
        if timestamp is None:
            timestamp = raw_log.get("timestamp") or raw_log.get("received_at")
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        elif isinstance(timestamp, (int, float)):
            timestamp = datetime.fromtimestamp(timestamp).isoformat()
        elif isinstance(timestamp, str):
            try:
                if timestamp.endswith("Z"):
                    timestamp = timestamp[:-1] + "+00:00"
                timestamp = datetime.fromisoformat(timestamp).isoformat()
            except:
                pass
        return str(timestamp)

    @staticmethod
    def _extract_date(timestamp: str) -> float:
        try:
            if timestamp.endswith("Z"):
                timestamp = timestamp[:-1] + "+00:00"
            return datetime.fromisoformat(timestamp).timestamp()
        except:
            try:
                return float(timestamp)
            except:
                return time.time()

    @staticmethod
    def _format_timestamp(timestamp: str) -> str:
        try:
            if timestamp.endswith("Z"):
                timestamp = timestamp[:-1] + "+00:00"
            return datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M:%S %z")
        except:
            return timestamp

    @staticmethod
    def _get_string_field(source: Dict[str, Any], field_names: list, default: str = "N/A") -> str:
        for field in field_names:
            value = source.get(field)
            if value not in (None, ""):
                return str(value)
        return default

    @staticmethod
    def _get_numeric_field(source: Dict[str, Any], field_names: list, default: int = 0) -> int:
        for field in field_names:
            value = source.get(field)
            if value is not None:
                try:
                    return int(value)
                except:
                    try:
                        return int(float(value))
                    except:
                        continue
        return default

    @staticmethod
    def _ensure_schema_order(formatted: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure all fields are present and in correct order"""
        result = {}
        for field in LogFormatter.SCHEMA_FIELDS:
            value = formatted.get(field)
            # Drop empty / default noise fields
            if value in (None, "N/A", "", 0, "False"):
                continue

            result[field] = value

        return result

    @staticmethod
    def format_logs_batch(raw_logs: list) -> list:
        return [LogFormatter.format_log(log) for log in raw_logs]
