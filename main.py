"""
Notepad TabState parser by @aniqfakhrul.
"""
from datetime import datetime, timezone
from enum import Enum
from binascii import hexlify
from dataclasses import dataclass

class FileEncoding(Enum):
	ANSI = 0x01
	UTF_16LE = 0x02
	UTF_16BE = 0x03
	UTF_8BOM = 0x04
	UTF_8 = 0x05

class CarriageReturn(Enum):
	CRLF = 0x01
	CR = 0x02
	LF = 0x03

@dataclass
class UnsavedChunk:
	cursor_position: bytes
	deletion_number: bytes
	addition_number: bytes
	chars: bytes
	checksum: bytes

@dataclass
class ConfigBlock:
	word_wrap: bool
	rtl: bool
	show_unicode: bool
	version: bool
	unknown0: bytes

@dataclass
class SavedTab:
	signature: str
	sequence_number: bytes
	type_flag: bool
	path_length: bytes
	file_path: bytes
	file_size: bytes
	encoding: bytes
	cr_type: bytes
	last_write_time: bytes
	sha256_hash: bytes
	unknown0: bytes
	selection_start: bytes
	selection_end: bytes
	config_block: ConfigBlock
	content_length: bytes
	content: bytes
	contain_unsaved_data: bool
	checksum: bytes
	#unsaved_chunks: UnsavedChunk

@dataclass
class UnsavedTab:
	signature: bytes
	sequence_number: bytes
	type_flag: bool
	unknown1: bytes
	selection_start: bytes
	selection_end: bytes
	config_block: ConfigBlock
	content_length: bytes
	content: bytes
	contain_unsaved_data: bool
	checksum: bytes
	#unsaved_chunks: UnsavedChunk

class TabStateParser:
	"""
	Notepad Tabstate file parser object. Inspired by https://u0041.co/posts/articals/exploring-windows-artifacts-notepad-files/
	"""
	def __init__(self, file_path=None, raw=False):
		self.file_path = file_path
		self.file_stream = open(self.file_path, "rb")
		self.raw = raw

	# Read the LEB128 encoded integer from a stream
	def read_leb128_unsigned(self, stream) -> int:
		result = 0
		shift = 0
		while True:
			b = stream.read(1)
			if len(b) == 0:
				raise EOFError("Unexpected end of stream while reading LEB128 value")
			byte_value = b[0]
			result |= ((byte_value & 0x7F) << shift)
			shift += 7
			if byte_value >> 7 == 0:
				break
		return result

	def to_datetime(self, filetime: int) -> datetime:
		"""
		Function is taken from https://github.com/jleclanche/winfiletime/blob/master/winfiletime/filetime.py
		"""
		# Get seconds and remainder in terms of Unix epoch
		s, ns100 = divmod(filetime - 116444736000000000, 10000000)
		# Convert to datetime object, with remainder as microseconds.
		return datetime.utcfromtimestamp(s).replace(microsecond=(ns100 // 10))
 
	def valid_header(self, header_bytes: bytes) -> bool:
		return header_bytes == b'NP'

	def parse_unsaved_chunk(self) -> UnsavedChunk:
		cursor_position = self.read_leb128_unsigned(self.file_stream)
		deletion_number = self.read_leb128_unsigned(self.file_stream)
		addition_number = self.read_leb128_unsigned(self.file_stream)
		chars = self.file_stream.read(addition_number * 2)
		checksum = self.file_stream.read(4)
		return UnsavedChunk(
			cursor_position=cursor_position,
			deletion_number=deletion_number,
			addition_number=addition_number,
			chars=chars,
			checksum=checksum
		)

	def parse_config_block(self) -> ConfigBlock:
		word_wrap = self.file_stream.read(1)
		rtl = self.file_stream.read(1)
		show_unicode = self.file_stream.read(1)
		version = self.file_stream.read(1)
		if version == b'\x02':
			unknown0 = self.file_stream.read(2)
		elif version == b'\x01':
			unknown0 = self.file_stream.read(1)
		else:
			unknown0 = b''
		return ConfigBlock(
			word_wrap=word_wrap if self.raw else bool(ord(word_wrap)),
			rtl=rtl if self.raw else bool(ord(rtl)),
			show_unicode=show_unicode if self.raw else bool(ord(show_unicode)),
			version=version if self.raw else ord(version),
			unknown0=unknown0 if self.raw else unknown0.decode("utf-8")
		)

	def parse_saved(self, file_stream=None):
		if not file_stream:
			file_stream = self.file_stream

		signature = file_stream.read(2)
		if not self.valid_header(signature):
			raise Exception("Invalid file signature")

		seqNumber = self.read_leb128_unsigned(file_stream)
		typeFlag = self.read_leb128_unsigned(file_stream)
		if typeFlag != 1:
			raise Exception("Not a saved file")
		fPathLength = self.read_leb128_unsigned(file_stream)
		fPathBytes = file_stream.read(fPathLength * 2)
		fSize = self.read_leb128_unsigned(file_stream)
		encoding = file_stream.read(1)
		crType = file_stream.read(1)
		timestamp = self.read_leb128_unsigned(file_stream)
		sha256Hash = file_stream.read(32)
		unk0 = file_stream.read(2)
		cursorSelectionStart = self.read_leb128_unsigned(file_stream)
		cursorSelectionEnd = self.read_leb128_unsigned(file_stream)
		configBlock = self.parse_config_block()
		contentCharLength = self.read_leb128_unsigned(file_stream)
		fContentBytes = file_stream.read(contentCharLength * 2)
		containUnsavedData = file_stream.read(1)
		crc32Checksum = file_stream.read(4)

		return SavedTab(
			signature=signature if self.raw else signature.decode("utf-8"),
			sequence_number=seqNumber,
			type_flag=typeFlag if self.raw else bool(typeFlag),
			path_length=fPathLength,
			file_path=fPathBytes if self.raw else fPathBytes.decode("utf-16-le"),
			file_size=fSize,
			encoding=encoding if self.raw else FileEncoding(ord(encoding)).name,
			cr_type=crType if self.raw else CarriageReturn(ord(crType)).name,
			last_write_time=timestamp if self.raw else self.to_datetime(timestamp),
			sha256_hash=sha256Hash if self.raw else hexlify(sha256Hash).decode("utf-8"),
			unknown0=unk0,
			selection_start=cursorSelectionStart,
			selection_end=cursorSelectionEnd,
			config_block=configBlock,
			content_length=contentCharLength,
			content=fContentBytes if self.raw else fContentBytes.decode("utf-16-le"),
			contain_unsaved_data=containUnsavedData if self.raw else bool(containUnsavedData),
			checksum=crc32Checksum if self.raw else hexlify(crc32Checksum).decode("utf-8"),
		)

	def parse_unsaved(self, file_stream=None):
		if not file_stream:
			file_stream = self.file_stream

		signature = file_stream.read(2)
		if not self.valid_header(signature):
			raise Exception("Invalid file signature")

		seqNumber = self.read_leb128_unsigned(file_stream)
		typeFlag = self.read_leb128_unsigned(file_stream)
		if typeFlag != 0:
			raise Exception("Not an unsaved file")
		fPathLength = self.read_leb128_unsigned(file_stream)
		unk1 = file_stream.read(1)
		cursorSelectionStart = self.read_leb128_unsigned(file_stream)
		cursorSelectionEnd = self.read_leb128_unsigned(file_stream)
		configBlock = self.parse_config_block()
		fContentLength = self.read_leb128_unsigned(file_stream)
		fContentBytes = file_stream.read(fContentLength * 2)
		containUnsavedData = file_stream.read(1)
		crc32Checksum = file_stream.read(4)

		return UnsavedTab(
			signature=signature if self.raw else signature.decode("utf-8"),
			sequence_number=seqNumber,
			type_flag=typeFlag if self.raw else bool(typeFlag),
			unknown1=unk1,
			selection_start=cursorSelectionStart,
			selection_end=cursorSelectionEnd,
			config_block=configBlock,
			content_length=fContentLength,
			content=fContentBytes if self.raw else fContentBytes.decode("utf-16-le"),
			contain_unsaved_data=containUnsavedData if self.raw else bool(containUnsavedData),
			checksum=crc32Checksum if self.raw else hexlify(crc32Checksum).decode("utf-8"),
		)

	def parse(self):
		"""
		Parsing "UnsavedTab" and "SavedTab" TabState structure.
		Credits to https://u0041.co/posts/articals/exploring-windows-artifacts-notepad-files/
		"""
		fHeader = self.file_stream.read(5)
		signature = fHeader[:2]
		if not self.valid_header(signature):
			raise Exception("Invalid file signature")

		typeFlag = fHeader[3]
		self.file_stream.seek(0)

		if typeFlag == 0:
			return self.parse_unsaved()
		elif typeFlag == 1:
			return self.parse_saved()
		else:
			raise Exception("Invalid buffer file type")