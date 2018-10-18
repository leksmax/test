#!/usr/bin/perl -w
# Copyright (c) 2017 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.

use File::Copy;

my $OutputDir = "outputTemplate";
my $HDir = "../include";
my $CDir = "../src";

if (!(-d $OutputDir) || (isEmpty($OutputDir)))
{
	print "No files generated\n";
}
else
{
	my @clist = <$OutputDir/*.c>;
	foreach my $file(@clist)
	{
		move ($file, $CDir) or print "Error: cannot update ../src with $file. Check-out the file first\n";
	}
	my @hlist = <$OutputDir/*.h>;
	foreach my $file(@hlist)
	{
		move ($file, $HDir) or print "Error: cannot update ../include with $file. Check-out the file first\n";
	}
}

#--------------------
sub isEmpty
{
	opendir (DIR, shift) or die $!;
	my @files = grep { !m/\A\.{1,2}\Z/} readdir(DIR);
	closedir(DIR);
	@files ? 0 : 1;
}
