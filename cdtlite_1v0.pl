$::help=<<EOHelp;
$0 [-h] [-v]

ProgramId : "CDTlite"
Author : "G D Geen"
DateWritten : "19 Aug 2015"
DateUpdated : "19 Feb 2016"
Version : "1.0"

The program collects operating system information and OfficeScan client and server
related log files and configuration files.  What we collect:
* SystemInfo.nfo
* Application.evtx
* System.evtx
* Registry entries related to OfficeScan client and server
* OfficeScan configuration files
* existing OfficeScan log files.

At no time do we modify any regitry keys to enable or disable any services. This
program is collecting of existing information only.  For more detailed log collection
please use or CaseDiagnosticTool; http://downloadcenter.trendmicro.com


-h	:  Help, this text.
-v      :  Verbose mode.  Allows the user to see a summary of the activity being performed.

22 Oct 2015 - change capture of operating system event logs from 1 day to 7 days.
 7 Nov 2015 - Change compression type to .zip
13 Nov 2015 - Added client and server side ssnotify.ini file
            - Added ipconfig command to .txt file
            - Added netstat -na command to .txt file
 7 Dec 2015 - Added HKLM\SYSTEM\CurrentControlSet\services as Reg05.reg
15 Dec 2015 - Added Product.ini file for TMCM connectivity information
            - Some commands were executed from the hardcoded windows path rather than
              relying on the environment variables to determin the windows install path.
18 Dec 2015 - Add password, trend, to zip file.
27 Jan 2016 - Add Agent.ini to collect TMCM configuration information for the OSCE server.
19 Feb 2016 - Add scan_operation logs, and malware detection logs: AEGIS_BM, CCCACIn, NCIE, pccnt32, spyware.
EOHelp


MAIN: 
{

require "geen_lib.pm";
use Encode::Guess;	#needed to guess encoding type.
use File::Copy;		#needed for simplfied file copy.

#get number of seconds since the EPOCH
my $secEPOCH = time();
my $lastweek = $secEPOCH - (86400*7);
my ($nobit64, $verbose) = 0;

#Convert EPOCH and last week to something a little more readable.
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($secEPOCH);
my ($ysec,$ymin,$yhour,$ymday,$ymon,$yyear,$ywday,$yyday,$yisdst) = localtime($lastweek);

$year+=1900;
$mon+=1;
$mon=&zero_pad($mon);
$mday=&zero_pad($mday);
$hour=&zero_pad($hour);
$min=&zero_pad($min);
$sec=&zero_pad($sec);


$yyear+=1900;
$ymon+=1;
$ymon=&zero_pad($ymon);
$ymday=&zero_pad($ymday);
$yhour=&zero_pad($yhour);
$ymin=&zero_pad($ymin);
$ysec=&zero_pad($ysec);

my $dtstring=$year.$mon.$mday."T".$hour.$min.$sec;
my ($programfiles, $progfilesx86, $nobit64, $sysroot, $sysdrive, $windir, $tempdir, $computername, $fnprefix)=("","",0,"","","","","","");


while (@ARGV)
	{
	my $element = shift(@ARGV);
	SWITCH:
		{
		if ($element eq "-h") { print "$::help"; exit 0; }
		if ($element eq "-v") { $verbose=1; last; }
		print "$::help"; exit 1; 
		}	#end SWITCH tree.
	}	#end while @ARGV is still populated.

########################################################################
#Get environment variables
########################################################################
print "Getting a few environment variables...\n" if $verbose;
$programfiles="$ENV{ProgramFiles}";
if ( $ENV{'ProgramFiles(x86)'} ) 
    { $progfilesx86="$ENV{'ProgramFiles(x86)'}"; 
    $nobit64=1; 
    }
else { $nobit64=0; }
$sysroot="$ENV{SystemRoot}";
$sysdrive="$ENV{SystemDrive}";
$windir="$ENV{windir}";
$tempdir="$ENV{TEMP}";
$computername="$ENV{COMPUTERNAME}";

########################################################################
# Create a file name prefis with the comptuer name and date/time string.
########################################################################
$fnprefix=$computername."_".$dtstring;

########################################################################
#create directory structure to hold collected data
########################################################################
mkdir $fnprefix;
mkdir "$fnprefix/server";
mkdir "$fnprefix/client";
chdir $fnprefix;

########################################################################
#Get network information in .txt file format
########################################################################
print "Getting network information...\n" if $verbose;
system("$windir\\System32\\ipconfig.exe > ip_config.txt");
system("$windir\\System32\\netstat.exe -na> netstat-na.txt");

########################################################################
#Get system information in .nfo file format
########################################################################
print "Getting system information...\n" if $verbose;
system("$windir\\System32\\msinfo32.exe /nfo system.nfo");

########################################################################
#Get task list of running processes
########################################################################
print "Getting list of running processes...\n" if $verbose;
system ("$windir\\System32\\tasklist.exe > tasklist.txt");

########################################################################
#Get list of registered applications
########################################################################
print "Getting list of registered programs...\n" if $verbose;
system("$windir\\System32\\wbem\\WMIC.exe /output:ProgramList.txt product get name,version");


########################################################################
#Get list of running services
########################################################################
print "Getting list of running services...\n" if $verbose;
system("$windir\\System32\\sc.exe query type= service > services.txt");

########################################################################
#Get application and system event logs from the last 24 hours.
########################################################################
$ymday=&zero_pad($ymday);
$ymon=&zero_pad($ymon);
$hour=&zero_pad($hour);
$min=&zero_pad($min);
$sec=&zero_pad($sec);

print "Getting System event logs...\n" if $verbose;
system("$windir\\System32\\wevtutil.exe epl System /q:\"\*[System[TimeCreated[\@SystemTime>='${yyear}-${ymon}-${ymday}T${hour}:${min}:${sec}']]]\" System.evtx");
# print "$windir\\System32\\wevtutil.exe epl System /q:\"\*[System[TimeCreated[\@SystemTime>='${yyear}-${ymon}-${ymday}T${hour}:${min}:${sec}']]]\" System.evtx";
sleep 30;
print "Getting Application event logs...\n" if $verbose;
system("$windir\\System32\\wevtutil.exe epl Application /q:\"\*[System[TimeCreated[\@SystemTime>='${yyear}-${ymon}-${ymday}T${hour}:${min}:${sec}']]]\" Application.evtx");
# print "$windir\\System32\\wevtutil.exe epl Application /q:\"\*[System[TimeCreated[\@SystemTime>='${yyear}-${ymon}-${ymday}T${hour}:${min}:${sec}']]]\" Application.evtx";

########################################################################
#Get registry dumps.
########################################################################
#All
system("$windir\\System32\\reg.exe export HKLM\\SOFTWARE\\TrendMicro Reg01.reg");
system("$windir\\System32\\reg.exe export HKLM\\SYSTEM\\CurrentControlSet\\services Reg05.reg");

#64bit
if ( $nobit64 == 1 )
    {
    system("$windir\\System32\\reg.exe export HKLM\\SOFTWARE\\Wow6432Node\\TrendMicro Reg02.reg");

    #server only
    system("$windir\\System32\\reg.exe export \"HKLM\\SOFTWARE\\Wow6432Node\\Trend Micro Inc.\" Reg03.reg");
    }
else
    {
    #32bit
    system("$windir\\System32\\reg.exe export \"HKLM\\SOFTWARE\Trend Micro Inc.\" Reg04.reg");
    }

print "Getting client and server install path...\n" if $verbose;
my ($local_path, $app_path)=&GetAppPath($nobit64);
#chomp($local_path);
#chomp($app_path);


########################################################################
# Get client configuration data
########################################################################
print "Getting client configuration files...\n" if $verbose;
if ( $app_path ne "" )
    {
    copy("${app_path}ofcscan.ini","client/ofcscan.ini") || warn "WARNING: Could not copy ofcscan.ini: $!\n";
    copy("${app_path}ous.ini","client/ous.ini") || warn "WARNING: Could not copy ous.ini: $!\n";
    copy("${app_path}hotfix_history.ini","client/hotfix_history.ini") || warn "WARNING: Could not copy hotfix_history.ini: $!\n";
    copy("${app_path}ssnotify.ini","client/ssnotify.ini") || warn "WARNING: Could not copy ssnotify.ini: $!\n";
    }

########################################################################
# Get client log data.
########################################################################
print "Getting client log files...\n" if $verbose;
if ( -e "${windir}\\OFCNT.log" ) { copy("${windir}\\ofcnt.log","client/OFCNT.log") || warn "WARNING: Could not copy ofcnt.log: $!\n"; }
if ( -e "${tempdir}\\OFCNT.log" ) { copy ("${tempdir}\\ofcnt.log","client/OFCNT.log") || warn "WARNING: could not copy ofcnt.log: $!\n"; }
if ( -e "${sysdrive}\\TmPatch.log" ) { copy ("${sysdirve}\\TmPatch.log","client/TmPatch.log") || warn "WARNING could not copy TmPatch.log: $!\n"; }
if ( -e "${windir}\\setupapi.log" ) { copy("${windir}\\setupapi.log","client/setupapi.log") || warn "WARNING: Could not copy setupapi.log: $!\n"; }
if ( -e "${windir}\\inf\\setupapi.app.log" ) { copy("${windir}\\inf\\setupapi.app.log","client/setupapi.app.log") || warn "WARNING: Could not copy setupapi.app.log: $!\n"; }
if ( -e "${windir}\\inf\\setupapi.dev.log" ) { copy("${windir}\\inf\\setupapi.dev.log","client/setupapi.dev.log") || warn "WARNING: Could not copy setupapi.dev.log: $!\n"; }




# get upgrade logs.
opendir(DIRFH, "${app_path}Temp");
my @files = grep { /upgrade_/ } readdir(DIRFH);
closedir(DIRFH);

foreach my $file ( @files ) 
	{ chomp($file); copy ("${app_path}Temp\\${file}", "client/$file"); }

# get connection logs.
@files = &GetFileList($app_path, "ConnLog", "Conn_");
foreach my $file ( @files )
	{ copy ("${app_path}ConnLog\\${file}", "client/$file"); }

# get malware logs.
@files = &GetFileList($app_path, "Misc", ".log");
foreach my $file ( @files )
	{ copy ("${app_path}Misc\\${file}", "client/$file"); }

if ( -e "${app_path}Misc\\scan_operation.csv" ) { copy ("${app_path}Misc\\scan_operation.csv", "client/scan_operation.csv") || warn "WARNING could not copy scan_operation.csv $!\n"; }

if ( -e "${app_path}AU_Data\\AU_Log\\TmuDump.txt" ) { copy ("${app_path}AU_Data\\AU_Log\\TmuDump.txt","client/TmuDump.txt") || warn "WARNING could not copy TmuDump.log: $!\n"; }

if ( -e "${app_path}OppLog\\OppLogs.log" ) { copy ("${app_path}OppLog\\OppLogs.log","client/OppLogs.log") || warn "WARNING could not copy OppsLogs.log: $!\n"; }

# get scan logs.
@files = &GetFileList($app_path, "Misc", "\.log");


########################################################################
# Get server configuration data.
########################################################################
if ( $local_path ne "" )
	{
	print "Getting server configuration files...\n" if $verbose;
	copy("${local_path}ofcscan.ini","server/ofcscan.ini") || warn "WARNING: Could not copy ofcscan.ini: $!\n";
	copy("${local_path}ous.ini","server/ous.ini") || warn "WARNING: Could not copy ous.ini: $!\n";
	copy("${local_path}Admin\\hotfix_history.ini","server/hotfix_history.ini") || warn "WARNING: Could not copy hotfix_history.ini: $!\n";
	copy("${local_path}Private\\ofcserver.ini","server/ofcserver.ini") || warn "WARNING: Could not copy ofcserver.ini: $!\n";
	copy("${local_path}Admin\\getserver.ini","server/getserver.ini") || warn "WARNING: Could not copy getserver.ini: $!\n";
	copy("${local_path}Admin\\ssnotify.ini","server/ssnotify.ini") || warn "WARNING: Could not copy ssnotify.ini: $!\n";
	copy("${local_path}CmAgent\\Product.ini","server/Product.ini") || warn "WARNING: Could not copy Product.ini: $!\n";
	copy("${local_path}CmAgent\\Agent.ini","server/Agent.ini") || warn "WARNING: Could not copy Agent.ini: $!\n";

########################################################################
# Get server logs data.
########################################################################
	print "Getting server log files...\n" if $verbose;
	copy("${sysdrive}/TMPatch.log", "server/TMPatch.log") || warn "WARNING: could not copy TMPatch.log: $!\n";
	copy("${windir}/OFCMAS.LOG", "server/OFCMAS.LOG") || warn "WARNING: could not copy OFCMAS.LOG: $!\n";
	copy("${local_path}Web\\Service\\AU_Data\\AU_Log\\TmuDump.txt","server/TmuDump.txt") || warn "WARNING: Could not copy TmuDump.txt: $!\n";
	copy("${local_path}LWCS\\access.log","server/LWCS_access.log") || warn "WARNING: Could not copy LWCS_access.log: $!\n";
	copy("${local_path}WSS\\access.log","server/WSS_access.log") || warn "WARNING: Could not copy WSS_access.log: $!\n";
	copy("${local_path}diagnostic.log","server/diagnostic.log") || warn "WARNING: Could not copy diagnostic.log: $!\n";
	copy("${local_path}LWCS\\diagnostic.log","server/LWCS_diagnostic.log") || warn "WARNING: Could not copy LWCS_diagnostic.log: $!\n";
	copy("${local_path}WSS\\diagnostic.log","server/WSS_diagnostic.log") || warn "WARNING: Could not copy WSS_diagnostic.log: $!\n";
	copy("${local_path}web\\Service\\diagnostic.log","server/web_Service_diagnostic.log") || warn "WARNING: Could not copy web_Service_diagnostic.log: $!\n";
	}



########################################################################
# Compress data with password "trend" to .zip file
########################################################################
print "Compressing data...\n" if $verbose;
chdir "..";
# system("\"${app_path}7z.exe\" a -bd ${fnprefix}.7z $fnprefix");
# system("\"${app_path}7z.exe\" a ${fnprefix}.zip -tzip $fnprefix");
system("\"${app_path}7z.exe\" a -ptrend -tzip ${fnprefix}.zip  $fnprefix");
exit 0;
}	#end MAIN:

sub GetAppPath
########################################################################
# GetAppPath, retreives the application and local path from the 
# registry infromation files.  The subroutine takes the nobit64 
# parameter to determine if the information provided is for 32 bit or
# 64 bit computer.  The program test encoding to properly open the file,
# being either ascii or UTF-16.
########################################################################
{


local ($nobit64)=@_;
local ($app_path, $local_path, $infile)=("","","");
local $record;
local $INFH;
local $encoding="";

#REGEDIT4  == plain text
#Windows Registry Editor Version 5.00 == UTF-16 encoding (returns 0 if found 256 if not found)

############################################################
# Decide which registry file to read.  For 64bit systems
# read Reg02.reg.  For 32bit system then read Reg01.reg.
############################################################
if ( $nobit64 == 1 )
	{ $infile = "Reg02.reg"; }
else
	{ $infile = "Reg01.reg"; }

############################################################
# Deterine the encoding type.  On 32bit systems the .reg 
# file was just plain ASCII but from 64bit operating 
# systems the .reg file is UTF-16 encoded.
############################################################
open($INFH,"$infile");
binmode($INFH);
if(read($INFH,my $filestart, 500)) 
    {
    $encoding = guess_encoding($filestart);
    if(ref($encoding)) { $encoding=($encoding->name);}
	else { $encoding=""; }
    }
close($INFH);

# print "$encoding\n";
#ascii
#UTF-16

############################################################
# open the file up in either ascii or UTF-16 depending on
# the encoding type.
############################################################
if ( $encoding eq "ascii" )
	{ open ($INFH, "$infile"); }	#end if file encoding is ascii
elsif ( $encoding eq "UTF-16" )
	{ open( $INFH, "<:encoding(UTF-16)", $infile); }	#End elsif file encoding is UTF-16
else 	{ return ""; }	#else I do not know file encoding


############################################################
# Open the registry file and search for Local_Path, the
# path to the server install, and serch for Application
# Path, the location of the client applction install.
############################################################
while ( $record=<$INFH> )
	{
	if ( $record =~ /^\"Local_Path\".*/ ) 
		{ 
		my @stuff=split(/"\s*/, $record);
		#$stuff[3]=~s/\\\\/\\/g;
		$local_path=$stuff[3];
		}	#end if record is server directory
	if ( $record =~ /^\"Application Path\".*/) 
		{
		my @stuff=split(/"\s*/, $record);
		#$stuff[3]=~s/\\\\/\\/g;
		$app_path=$stuff[3];

		}	#end if record is client directory
	}	#end while not end of file $INFH

close $INFH;

return($local_path, $app_path);

# Reg02.reg -- server install path
# "Local_Path"="c:\\program files (x86)\\Trend..."
# Reg02.reg -- client install path
# "Application Path"="c:\\program files..."

}	#end sub GetAppPath

sub GetFileList
############################################################
# Get a list of files matching a specified criteria
############################################################
{
($app_path, $file_path, $filestring)=@_;

opendir(DIRFH, "${app_path}$file_path");
my @files = grep { /$filestring/ } readdir(DIRFH);
closedir(DIRFH);
return(@files);
}	#end sub GetFileList
