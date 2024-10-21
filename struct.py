#!/usr/bin/env python3
from impacket.structure import structure
from enum import Enum

class Constants(Enum):
	ULEB128 = '<B=-'

class Flag(Enum):
	Unsaved = 0x00
	Saved = 0x01

class encodingType(Enum):
	ANSI = 0x01
	UTF_16LE = 0x02
	UTF_16BE = 0x03
	UTF_8BOM = 0x04
	UTF_8 = 0x05

class carriageType(Enum):
	CRLF = 0x01
	CR = 0x02
	LF = 0x03

class NPSavedState(Structure):
	structure = (
		('signature', 'B'),
		('sequenceNumber', 'B'),
		('Flag', Flag),
		('path', 'B'),
		('lenPath', 'B'),
		('filePath', 'B'),
		('fileSize', 'B'),
		('encodingType', 'B'),
		('carriageType', 'B'),
		('timeStamp', 'B'),
		('fileHash', 'B'),
		('selectionStart', ''),
		('selectionEnd', ''),
		('NPConfigBlock', NPConfigBlock),
		('contentLen', 'B'),
		('content', 'B'),
		('unsavedData', 'B'),
		('CRC32checkSum', 'B'),
		('NPUnsavedChunkStruct', NPUnsavedChunkStruct),
	)

class NPUnsavedState(Structure):
	structure = (
		('signature', 'B'),
		('unknown0', 'B'),
		('path', ''),
		('unknown1', 'B'),
		('selectionStart', ''),
		('selectionEnd', ''),
		('NPConfigBlock', NPConfigBlock),
		('contentLen', ''),
		('content', ''),
		('unsavedData', ''),
		('CRC32checkSum', ''),
		('NPUnsavedChunkStruct', NPUnsavedChunkStruct),
	)

class CursorPosition(Structure):
	structure = (
		('selectionStart',''),
		('selectionEnd',''),
		('addNum',''),
		('deleteNum',''),
	)

class NPConfigBlock(Structure):
	structure = (
		('wrapWord', ''),
		('rightToLeft', ''),
		('unicode', ''),
		('version', ''),
		('unknownOptions', ''),
	)

class NPUnsavedChunkStruct(Structure):
	structure = (
		('CursorPosition', CursorPosition),
		('characters', ''),
		('CRC32checkSum', ''),
	)