__author__ = "SystematicSkid"

import os
import sys
import re

media_type = [
    "mp3",
    "mp4",
    "wav",
    "wma",
    "wmv",
    "mov",
    "avi",
    "mpg",
    "mpeg",
    "mkv",
    "flv",
    "ogg",
    "ogv",
    "3gp",
    "3g2",
    "m4a",
    "m4v",
    "flac",
    "aac",
    "opus",
    "webm",
    "amr",
    "m3u",
    "m3u8",
    "pls",
    "asx",
    "asf",
    "ram",
    "rm",
]
# Media Search Class
class MediaPolicyScanner:
    def __init__(self, directory = '/'):
        self.directory = directory

    def find_media_files( self ):
        # Get home directory
        home = os.path.join( self.directory, 'home' )
        # Recursively search for media files
        media_files = []
        for root, dirs, files in os.walk( home ):
            for file in files:
                if file.split( '.' )[ -1 ] in media_type:
                    media_files.append( os.path.join( root, file ) )
        return media_files