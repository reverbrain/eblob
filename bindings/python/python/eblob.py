import struct, os

class blob:
	format = '<64sQQQQ'
	index_size = struct.calcsize(format)

	FLAGS_REMOVED = 1

	def __init__(self, path, data_mode='r+b', index_mode='r+b'):
		self.dataf = open(path, data_mode)
		self.index = open(path + '.index', index_mode)

		self.position = 0
		self.next_position = 0
		self.id = ''
		self.data_size = 0
		self.disk_size = 0
		self.flags = 0
		self.data = ''

	def read_index(self):
		idata = self.index.read(self.index_size)
		if len(idata) != self.index_size:
			raise NameError('Finished index')

		self.id, self.flags, self.data_size, self.disk_size, self.position = struct.unpack(self.format, idata)
		self.read_data_index()

	def read_data_index(self):
		self.dataf.seek(self.next_position)
		ddata = self.dataf.read(self.index_size)
		if len(ddata) != self.index_size:
			raise NameError('Finished data')

		self.id, self.flags, self.data_size, self.disk_size, self.position = struct.unpack(self.format, ddata)
		self.next_position = self.position + self.disk_size
	
	def removed(self):
		return self.flags & self.FLAGS_REMOVED

	def mark_removed(self):
		self.flags |= self.FLAGS_REMOVED

	def read_data(self):
		self.dataf.seek(self.position)
		self.data = self.dataf.read(self.disk_size)

		if len(self.data) != self.disk_size:
			raise NameError('Finished data')

	def update(self):
		idata = struct.pack(self.format, self.id, self.flags, self.data_size, self.disk_size, self.position)
		self.index.seek(-self.index_size, os.SEEK_CUR)
		self.index.write(idata)

		self.dataf.seek(self.position)
		self.dataf.write(idata)
	
	def write_index(self):
		idata = struct.pack(self.format, self.id, self.flags, self.data_size, self.disk_size, self.position)
		self.index.write(idata)

	def get_data(self):
		idata = struct.pack(self.format, self.id, self.flags, self.data_size, self.disk_size, self.position)
		return idata, self.data

	def iterate(self, want_removed=False, over_data=False):
		while True:
			if over_data:
				self.read_data_index()
			else:
				self.read_index()

			if want_removed:
				yield self.id

			if not self.removed():
				yield self.id

	def sid(self, count=6):
		ba = bytearray(self.id[0:count])
		ret = ''
		for i in range(count):
			ret += '%02x' % ba[i]

		return ret
