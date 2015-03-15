#!/usr/bin/env python3.2
"""
Author: Branon Santiago
FAT16 Assignment CS365 Forensics, Spring 2015

"""
import sys
import struct 

def usage():
	""" Print usage string and exit() """
	print("Usage:\n%s filename\n" % sys.argv[0])
	sys.exit()

class FAT:
	def __init__(self,offset,filename):
		'''
		The offset is passed in to get to the bootsector. When we seek to bytes later on, it is always relative to the bootsector,
		so we must add the offset to get the correct values.
		'''
		self.offset = int(offset)
		self.filename = filename
		self._fs_type = "FAT16"
			

	def open_image(self):
		'''
		Try to open a FAT16 image so that we can parse through the values in its boot sector.
		'''
		try:
			self.fd = open(self.filename,'rb')
		except:
			print("Error opening file", sys.exc_info()[0])
			sys.exit()

	def bytesPerSector(self):
		'''
		Finds the number of bytes per sector of the file system. This value can be found in bytes 11-12 of the file system.
		'''
		self.fd.seek(11+self.offset)
		try:
			data = self.fd.read(2+self.offset)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.bytes_per_sector = struct.unpack("<H",data[0:len(data)])[0]

	def sectorsPerCluster(self):
		'''
		The number of sectors per cluster is the value of byte 13. 
		'''
		self.fd.seek(13+self.offset)
		try:
			data = self.fd.read(1)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.sectors_per_cluster = struct.unpack("<H", data + b'\x00')[0]


	def getFileSystemType(self):
		'''
		Prints the file system type is hard-coded as FAT16 for this assignment.
		'''
		print("File System Type: %s" % self._fs_type)
		print("")

	def getOEM(self):
		'''
		Prints the OEM Name of the file system, found in bytes 3-10 of the file system boot sector.
		'''
		self.fd.seek(3+self.offset)
		try:
			data = self.fd.read(8)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.oem_name = bytes.decode(data[0:len(data)])
		print("OEM Name: %s" % self.oem_name)

	def getVolumeID(self):
		'''
		Prints the volume ID (in hex) of the file system. Found in bytes 39-42 of the file system boot sector.
		'''

		self.fd.seek(39+self.offset)
		try:
			data = self.fd.read(4)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.volume_ID = struct.unpack("<L",data[0:len(data)])
		print("Volume ID: 0x%08x" % self.volume_ID)

	def getVolumeLabel(self):
		'''
		Prints the volume label of the file system. Found in bytes 43-53 of the file system boot sector.
		'''
		self.fd.seek(43+self.offset)
		try:
			data = self.fd.read(11)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.volume_label = bytes.decode(data[0:len(data)])
		print("Volume Label (Boot Sector): %s" % self.volume_label)

	def getFSTLabel(self):
		'''
		Prints the FST label of the file system. Found in bytes 54-61 of the file system boot sector.
		'''
		self.fd.seek(54+self.offset)
		try:
			data = self.fd.read(8)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.fs_type_label = bytes.decode(data[0:len(data)])
		print("")
		print("File System Type Label: %s" % self.fs_type_label)
		print("")

	def getTotalRange(self):
		'''
		Prints the total number of sectors in the file system. Since the total number of sectors includes sector 0, 
		we must subract 1 for the actual range of sectors.
		'''
		self.fd.seek(19+self.offset)
		try:
			data = self.fd.read(2)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.total_range = (struct.unpack("<H",data[0:len(data)])[0]) -1
		'''
		If the total range is greater than what can be represented as two bytes, then the value in bytes 19-20 will be 0
		and bytes 32-35 will store a 32-bit value for the number of sectors in the file system.
		'''
		if(self.total_range == 0):
			self.fd.seek(32+self.offset)
			try:
				data = self.fd.read(4)
			except:
				print("Unexpected error while reading file:", sys.exc_info()[0])
				sys.exit()
			self.total_range = struct.unpack("<L",data[0:len(data)]) -1
		print("Total Range: 0 - %d" % self.total_range)
		print("Total Range in Image: 0 - %d" % (self.total_range -1))

	def getReservedSize(self):
		'''
		The size, in sectors, of the reserved area of the file system. Note that the reserved area begins in sector 0 of 
		the file system, so the range of the reserved area goes from 0 to (size of reserved area - 1).
		''' 
		self.fd.seek(14+self.offset)
		try:
			data = self.fd.read(2)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.reserved_area = struct.unpack("<H",data[0:len(data)])[0]
		print("* Reserved: 0 - %d" % (self.reserved_area -1))

	def getBootSector(self):
		'''
		Prints sector offset where the file system starts in the image.
		'''
		print("** Boot Sector: %d" % self.offset)

	def getFATS(self):
		'''
		Retrieves the number of FATS and their size(in clusters), then prints both.
		'''
		self.fd.seek(16+self.offset)
		try:
			data = self.fd.read(1)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.num_of_FATS = struct.unpack("<H", data + b'\x00')[0]

		self.fd.seek(22+self.offset)
		try:
			data = self.fd.read(2)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.size_of_FATS = struct.unpack("<H",data[0:len(data)])[0]

		counter = 0
		'''
		The beginning of the first FAT in the FAT area is immediately after the reserved area of the file system
		Thus, each following FAT will begin after the length of the last FAT + its offset.
		'''
		FAT_offset = self.reserved_area
		while counter < self.num_of_FATS:
			self.FAT_end = (self.size_of_FATS -1) + FAT_offset
			print("* FAT%d: %d - %d" % (counter,FAT_offset,self.FAT_end))
			FAT_offset = FAT_offset + self.size_of_FATS
			counter = counter + 1


	def getDataArea(self):
		'''
		Prints the range of the data area within the file system. It starts at the end of the last FAT and goes until the 
		end of the file system.
		'''
		self.data_area_offset = self.FAT_end + 1
		print("* Data Area: %d - %d" % (self.data_area_offset, self.total_range))

	def getRootDirectory(self):
		'''
		Prints the range of the root directory within the data area of the file system. In FAT16, the root directory is the
		start of the data area, which is the end of the last FAT entry. The maximum number of files within the root directory 
		is the value of bytes 17-18. Each entry in the root directory is 32 bytes. Therefore, we can calculate the number of sectors 
		for the root directory as:
		((number of files in root directory) * (the number of bytes per entry))/(number of bytes per sector) 
		'''
		self.fd.seek(17+self.offset)
		try:
			data = self.fd.read(2)
		except:
			print("Unexpected error while reading file:", sys.exc_info()[0])
			sys.exit()
		self.files_in_rootdir = struct.unpack("<H",data[0:len(data)])[0]
		
		self.root_dir_size = (self.files_in_rootdir * 32)/(self.bytes_per_sector)
		self.root_dir_end = self.FAT_end + self.root_dir_size 
		print("** Root Directory: %d - %d" % (self.data_area_offset, self.root_dir_end))

	def getClusterArea(self):
		'''
		Prints the range of the cluster area which, in FAT16, begins right after the root directory.
		The cluster area is the range of clustered entries, which does not include unused sectors. 
		To find the unused sectors, take the total number of sectors and subtract the addresss of the end
		of the root directory, then mod that difference by the number of sectors per cluster. The remainder of the mod operation will yield 
		the amount, if any, of sectors that did not fill out another cluster. The cluster area will not include the unclustered sectors, so 
		the number ofremaining clusters is subracted from the total range of sectors, which gives us the cluster area.
		'''
		self.remaining_clusters = (self.total_range - self.root_dir_end)%self.sectors_per_cluster
		self.cluster_area = self.total_range - self.remaining_clusters
		print("** Cluster Area: %d - %d" % (self.root_dir_end + 1, self.cluster_area))

	def getNonClustered(self):
		'''
		Prints the range of non-clustered sectors in the data area of the file system.These appear right after
		the end of the cluster area until the end of the data area.
		'''
		print("** Non-clustered: %d - %d" % (self.cluster_area +1, self.total_range))

	def getClusterRange(self):
		'''
		Gets the begining and ending cluster numbers within the cluster area. Because the root directory is always the starting cluster,
		the cluster range will always start at cluster 2. The last cluster can be found by subtracting the beginning index of the clustered area,
		which is right after the end of the root directory, from the total cluster area, then dividing that number by the number of sectors per cluster.
		'''
		self.cluster_offset = 2
		self.last_cluster = self.cluster_offset+ ((self.cluster_area - (self.root_dir_end+1))/self.sectors_per_cluster)
		print("Total Cluster Range: %d - %d" % (self.cluster_offset,self.last_cluster))
def main():
	test_Fat = FAT(sys.argv[1],sys.argv[2])
	test_Fat.open_image()
	test_Fat.bytesPerSector()
	test_Fat.sectorsPerCluster()
	print("FILE SYSTEM INFORMATION")
	print("-------------------------------------------")
	test_Fat.getFileSystemType()
	test_Fat.getOEM()
	test_Fat.getVolumeID()
	test_Fat.getVolumeLabel()
	test_Fat.getFSTLabel()
	print("File System Layout (in sectors)")
	test_Fat.getTotalRange()
	test_Fat.getReservedSize()
	test_Fat.getBootSector()
	test_Fat.getFATS()
	test_Fat.getDataArea()
	test_Fat.getRootDirectory()
	test_Fat.getClusterArea()
	test_Fat.getNonClustered()
	print("")
	print("CONTENT INFORMATION")
	print("-------------------------------------------")
	print("Sector Size: %d bytes" % test_Fat.bytes_per_sector)
	print("Cluster Size: %d bytes" % (test_Fat.bytes_per_sector * test_Fat.sectors_per_cluster))
	test_Fat.getClusterRange()



# Standard boilerplate to run main()
if __name__ == '__main__':
	main()