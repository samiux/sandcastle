#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
source #1 by ysx            : https://github.com/0xSearches/sandcastle
source #2 by Parasimpaticki : https://github.com/Parasimpaticki/sandcastle

Modified by Samiux on October 03, 2019 (Version 1.4.3)

Since aws command line is changed, the aws commands are no longer working for S3 Buckets enumeration.

'''
#import sys, os, commands, requests, random, string
import sys, os, requests, random, string
from threading import BoundedSemaphore, Thread
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from argparse import ArgumentParser

print ("""
   ____             __             __  __   
  / __/__ ____  ___/ /______ ____ / /_/ /__ 
 _\ \/ _ `/ _ \/ _  / __/ _ `(_-</ __/ / -_)
/___/\_,_/_//_/\_,_/\__/\_,_/___/\__/_/\__/ 
                                            
S3 bucket enumeration // release v1.4.3 // ysx, Parasimpaticki & Samiux

WARNING : Don't run this script too often as AWS S3 will BAN you FOREVER from accessing the buckets!!!

""")

threadCount = 20 #Default

targetStem = ""
inputFile = ""
bucketFile = ""
availFormat = {"-",".",""}
availRegion = {"us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1", \
              "ap-east-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ap-southeast-2", "ap-south-1", "me-south-1", "sa-east-1"}


parser = ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-t", "--target", dest="targetStem",
                    help="Select a target stem name (e.g. 'shopify')", metavar="shopify")
group.add_argument("-f", "--file", dest="inputFile",
                    help="Select a target list file", metavar="targets.txt")
parser.add_argument("-b", "--bucket-list", dest="bucketFile",
                    help="Select a bucket permutation file (default: bucket-names.txt)", default="bucket-names.txt", metavar="bucket-names.txt")
parser.add_argument("--threads", dest="threadCount",
                    help="Choose number of threads (default=20)", default=20, metavar="20")
args = parser.parse_args()

semaphore = BoundedSemaphore(threadCount)

def checkBuckets(target,name):
        # according to the documentation of AWS, underscore is deleted.
        # https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-s3-bucket-naming-requirements.html
	for c in availFormat:
		for l in (True,False):
			if(l):
				bucketName = target + c + name
			else:
				bucketName = name + c + target

			try :
				r = requests.get("http://%s.s3.amazonaws.com" % bucketName)
			except:
				continue

			if "The specified bucket does not exist" not in r.text:
				print ("[+] Found a match: " + bucketName + " - http://" + bucketName + ".s3.amazonaws.com/")

				for s in availRegion:
					bucketRegion = s
					r2 = requests.get("http://" + bucketName + ".s3." + bucketRegion + ".amazonaws.com/")
					if "The bucket you are attempting to access must be addressed using the specified endpoint. Please send all future requests to this endpoint." not in r2.text and \
							"location constraint is incompatible for the region specific endpoint this request was sent to" not in r2.text:
						print ("[+] Found a match: " + bucketName + " - http://" + bucketName + ".s3." + bucketRegion + ".amazonaws.com/")

	semaphore.release()

def loadBuckets(target):
	threads = []
	for name in bucketNames:
		threads.append(Thread(target=checkBuckets, args=(name,target)))
	for thread in threads:  # Starts all the threads.
		semaphore.acquire()
		thread.start()
	for thread in threads:  # Waits for threads to complete before moving on with the main script.
		thread.join()

if __name__ == "__main__":
	with open(args.bucketFile, 'r') as b:
		bucketNames = [line.strip() for line in b]
		lineCount = len(bucketNames)
		print ("[*] Bucket Name list is loaded.")
		b.close()

	if(args.inputFile):
		with open(args.inputFile, 'r') as f:
			targetNames = [line.strip() for line in f]
			f.close()
		for target in targetNames:
			print ("[*] Commencing enumeration of '%s', reading %i lines from '%s'." % (target, lineCount, b.name))
			loadBuckets(target)
			print ("[*] Enumeration of '%s' buckets complete." % (target))
	else:
		print ("[*] Commencing enumeration of '%s', reading %i lines from '%s'." % (args.targetStem, lineCount, b.name))
		loadBuckets(args.targetStem)
		print ("[*] Enumeration of '%s' buckets complete." % (args.targetStem))

