#!/bin/sh

usage()
{
	echo "Usage         : vpn_genkey.sh rsa|ed25519 key_dir."
	echo "Description   : will generate vppn_pub.pem and vppn_priv.pem in key_dir."
	exit 1
}



gen_rsa()
{
	if [ -z $KEY_DIR ]; then
		usage
	else
		openssl genrsa -out $KEY_DIR/vppn_priv.pem -f4 2048
		openssl rsa -in $KEY_DIR/vppn_priv.pem -pubout -out $KEY_DIR/vppn_pub.pem
		#tinc gen-ed25519-keys $KEY_DIR/vppn_priv.pem $KEY_DIR/vppn_pub.pem
	fi
}

gen_ed25519()
{
	if [ -z $KEY_DIR ]; then
		usage
	else
		#openssl genrsa -out $KEY_DIR/vppn_priv.pem -f4 2048
		#openssl rsa -in $KEY_DIR/vppn_priv.pem -pubout -out $KEY_DIR/vppn_pub.pem
		tinc gen-ed25519-keys $KEY_DIR/vppn_priv.pem $KEY_DIR/vppn_pub.pem
	fi
}

if [ $# != 2 ]; then
	usage
fi

KEY_TYPE=$1
KEY_DIR=$2

if [ -z $KEY_TYPE ] || [ -z $KEY_DIR ]; then
	usage
fi

case $KEY_TYPE in
	rsa)
	gen_rsa
	;;
	ed25519)
	gen_ed25519
	;;
	*):
	usage
	;;
esac
