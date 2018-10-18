#!/usr/bin/perl -w
# Copyright (c) 2017 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.

use strict;
use File::Copy;

if (-d "outputTemplate")
{
	my @oldFiles = <outputTemplate/*>;
	unlink @oldFiles;
}
else
{
	mkdir "outputTemplate";
}


my $HALPHY_TOOLS_COMPONENT_DIR = "../../..";
my $INCLUDE_DIR = "$HALPHY_TOOLS_COMPONENT_DIR/tlvLib/tlv1/include";
my $EXE = "";

if ($#ARGV == 0 && $ARGV[0] =~ /linux/i)
{
    $EXE = "Linux/genParmTemplate.out";
}
elsif ($ARGV[0] =~ /darwin/i)
{
    my $DARWIN_GENPARMTEMPLATE = "../../../../art2_peregrine/src/art2/art2_MacOs/Build";
    
    if ($#ARGV == 1 && $ARGV[1] =~ /debug/i)
    {
        $EXE = "$DARWIN_GENPARMTEMPLATE/Debug/genParmTemplate";
    }
    else
    {
        $EXE = "$DARWIN_GENPARMTEMPLATE/Release/genParmTemplate";
    }
}
elsif ($ARGV[0] =~ /win/i && $ARGV[1] =~ /debug/i)
{
    $EXE = "Debug/genParmTemplate.exe";
}
else
{
    $EXE = "Release/genParmTemplate.exe";
}


system("$EXE $INCLUDE_DIR/cmdTxParms.h");
system("$EXE $INCLUDE_DIR/cmdRxParms.h");
system("$EXE $INCLUDE_DIR/cmdCalParms.h");

system("$EXE $INCLUDE_DIR/cmdCalDoneParms.h");
system("$EXE $INCLUDE_DIR/rspGenericParms.h");
system("$EXE $INCLUDE_DIR/submitReportParms.h");
system("$EXE $INCLUDE_DIR/cmdPmParms.h");
system("$EXE $INCLUDE_DIR/cmdSetRegParms.h");
system("$EXE $INCLUDE_DIR/cmdNartGenericCmdParms.h");
system("$EXE $INCLUDE_DIR/cmdNartGenericRspParms.h");
system("$EXE $INCLUDE_DIR/cmdTxStatus.h");
system("$EXE $INCLUDE_DIR/cmdRxStatus.h");
