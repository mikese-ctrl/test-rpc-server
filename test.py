#!/usr/bin/env python3

#
# Minimal NRPC PoC server for:
#   NetrLogonSamLogonWithFlags (opnum 45)
#
# Goal:
#   - Accept real Windows NRPC binds
#   - Handle opnum 45
#   - Extract username/domain/workstation from request
#   - Return minimally valid SAM_INFO_4 response
#
# NOTE:
#   This is ONLY a protocol PoC.
#   It does NOT implement real Netlogon security.
#   Modern Windows clients may still reject it depending
#   on signing/sealing/channel requirements.
#

from impacket.dcerpc.v5.rpcrt import DCERPCServer
from impacket.dcerpc.v5.nrpc import *
from impacket.uuid import uuidtup_to_bin

from impacket import LOG
import logging

logging.basicConfig(level=logging.DEBUG)

#
# NRPC UUID
#

NRPC_UUID = uuidtup_to_bin((
    '12345678-1234-abcd-ef00-01234567cffb',
    '1.0'
))


#
# Helpers
#

def build_empty_authenticator():
    auth = NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    return auth


def extract_identity(req):
    """
    Extract username/domain/workstation from request.
    Handles common logon levels.
    """

    username = "unknown"
    domain = "unknown"
    workstation = "unknown"

    try:
        level = req['LogonLevel']

        #
        # LOGON_LEVEL = NetlogonNetworkInformation
        #
        if level == 2:
            info = req['LogonInformation']['LogonNetwork']

            identity = info['Identity']

            username = str(identity['UserName'])
            domain = str(identity['LogonDomainName'])
            workstation = str(identity['Workstation'])

        #
        # LOGON_LEVEL = NetlogonInteractiveInformation
        #
        elif level == 1:
            info = req['LogonInformation']['LogonInteractive']

            identity = info['Identity']

            username = str(identity['UserName'])
            domain = str(identity['LogonDomainName'])
            workstation = str(identity['Workstation'])

    except Exception as e:
        print("Identity parse failed:", e)

    return username, domain, workstation


#
# opnum 45
#

def handle_samlogon(req):

    print("\n==============================")
    print("NetrLogonSamLogonWithFlags")
    print("==============================")

    req.dump()

    username, domain, workstation = extract_identity(req)

    print(f"Username    : {username}")
    print(f"Domain      : {domain}")
    print(f"Workstation : {workstation}")

    #
    # Build response
    #

    resp = NetrLogonSamLogonWithFlagsResponse()

    #
    # ReturnAuthenticator
    #

    resp['ReturnAuthenticator'] = build_empty_authenticator()

    #
    # ValidationLevel
    #
    # 3 = NetlogonValidationSamInfo4
    #

    resp['ValidationLevel'] = 3

    sam = NETLOGON_VALIDATION_SAM_INFO4()

    #
    # Populate from request
    #

    sam['EffectiveName'] = username
    sam['FullName'] = username

    sam['LogonScript'] = ""
    sam['ProfilePath'] = ""
    sam['HomeDirectory'] = ""
    sam['HomeDirectoryDrive'] = ""

    sam['LogonCount'] = 1
    sam['BadPasswordCount'] = 0

    sam['UserId'] = 1000
    sam['PrimaryGroupId'] = 513

    sam['GroupCount'] = 0
    sam['GroupIds'] = NULL

    sam['UserFlags'] = 0

    sam['UserSessionKey'] = b'\x00' * 16

    sam['LogonServer'] = "POC-SERVER"
    sam['LogonDomainName'] = domain

    #
    # Required-ish timestamps
    #

    sam['LogoffTime']['LowPart'] = 0xffffffff
    sam['LogoffTime']['HighPart'] = 0x7fffffff

    sam['KickOffTime']['LowPart'] = 0xffffffff
    sam['KickOffTime']['HighPart'] = 0x7fffffff

    sam['PasswordLastSet']['LowPart'] = 0
    sam['PasswordLastSet']['HighPart'] = 0

    sam['PasswordCanChange']['LowPart'] = 0
    sam['PasswordCanChange']['HighPart'] = 0

    sam['PasswordMustChange']['LowPart'] = 0xffffffff
    sam['PasswordMustChange']['HighPart'] = 0x7fffffff

    #
    # Put validation structure into union
    #

    resp['ValidationInformation']['ValidationSam4'] = sam

    resp['Authoritative'] = 1
    resp['ExtraFlags'] = 0

    #
    # STATUS_SUCCESS
    #

    resp['ErrorCode'] = 0

    print("\nSending response...\n")

    return resp


#
# Minimal challenge/auth support
#
# Windows clients often call these first.
#

def handle_reqchallenge(req):

    print("\nNetrServerReqChallenge")

    resp = NetrServerReqChallengeResponse()

    resp['ServerChallenge'] = b'12345678'
    resp['ErrorCode'] = 0

    return resp


def handle_auth3(req):

    print("\nNetrServerAuthenticate3")

    resp = NetrServerAuthenticate3Response()

    resp['ServerCredential'] = b'\x00' * 8
    resp['NegotiateFlags'] = 0x212fffff
    resp['AccountRid'] = 500

    #
    # STATUS_SUCCESS
    #

    resp['ErrorCode'] = 0

    return resp


#
# Server
#

server = DCERPCServer()

server.addCallbacks(NRPC_UUID, {

    #
    # opnum 4
    #
    4: handle_reqchallenge,

    #
    # opnum 26
    #
    26: handle_auth3,

    #
    # opnum 45
    #
    45: handle_samlogon,
})

#
# TCP endpoint
#

server.setListenPort(49667)

print("NRPC PoC listening on TCP/49667")

server.start()
