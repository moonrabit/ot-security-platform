from .modbus import ModbusAnalyzer
from .dnp3 import DNP3Analyzer
from .enip_cip import ENIPAnalyzer
from .opcua import OPCUAAnalyzer
from .bacnet import BACnetAnalyzer
from .iec104 import IEC104Analyzer
from .generic import GenericInsecureAnalyzer

ALL_ANALYZERS = [
    ModbusAnalyzer,
    DNP3Analyzer,
    ENIPAnalyzer,
    OPCUAAnalyzer,
    BACnetAnalyzer,
    IEC104Analyzer,
    GenericInsecureAnalyzer,
]
