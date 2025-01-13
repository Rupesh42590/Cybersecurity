""" 
Reflector:B
Rotors:IV-II-I
Plugboard:A-B,C-D,E-F
Message:A=>X
"""

import pygame
pygame.init()

from KEYBOARD import Keyboard
from PLUGBOARD import Plugboard
from ROTOR import Rotor
from REFLECTOR import Reflector
from ENIGMA import Enigma
from DRAW import draw

#setup pygame
pygame.init()
pygame.font.init()
pygame.display.set_caption("Enigma simulator")

#create fonts
MONO=pygame.font.SysFont("FreeMono",25)
BOLD=pygame.font.SysFont("FreeMono",25,bold=True)
#global variables
WIDTH=1560
HEIGHT=790
SCREEN=pygame.display.set_mode((WIDTH,HEIGHT))
MARGINS={"top":200,"bottom":100,"left":100,"right":100}
GAP=100

INPUT=""
OUTPUT=""
PATH=[]
cipher=""

#historical enigma rotors and reflectors
I=Rotor("EKMFLGDQVZNTOWYHXUSPAIBRCJ","Q")
II=Rotor("AJDKSIRUXBLHWTMCQGZNPYFVOE","E")
III=Rotor("BDFHJLCPRTXVZNYEIWGAKMUSQO","V")
IV=Rotor("ESOVPZJAYQUIRHXLNFTGKDCMWB","J")
V=Rotor("VZBRGITYUPSDNHLXAWMJQOFECK","Z")
A=Reflector("EJMZALYXVBWFCRQUONTSPIKHGD")
B=Reflector("YRUHQSLDPXNGOKMIEBFZCWVJAT")
C=Reflector("FVPJIAOYEDRZXWGCTKUQSBNMHL")

#keyboard and plugboard
KB=Keyboard()
PB=Plugboard(["AB","CD","EF"])

#define enigma machine
ENIGMA=Enigma(B,I,II,III,PB,KB)

#set the rings
ENIGMA.set_rings((1,1,1))


#set message key
ENIGMA.set_key("CAT")


#encipher message
#message="TESTINGTESTINGTESTING"
#cipher_text=""
#for letter in message:
#    encrypted_letter = ENIGMA.encipher(letter)
#    if encrypted_letter is not None:
#        cipher_text += encrypted_letter
#    """else:
#       # Handle the case when encryption fails (e.g., if the letter is not in the valid character set)
#       # You can choose to ignore the character, replace it, or handle it differently.
#        cipher_text += '?'  # Replacing with a question mark for illustration.
#       """
#print(cipher_text)

animating=True
while animating:
    
    #backgraound
    SCREEN.fill("#333333")
    
    #text input
    text=BOLD.render(INPUT,True,"white")
    text_box=text.get_rect(center=(WIDTH/2,MARGINS["top"]/3))
    SCREEN.blit(text,text_box)
    
    #text output
    text=BOLD.render(OUTPUT,True,"green")
    text_box=text.get_rect(center=(WIDTH/2,MARGINS["top"]/3+25))
    SCREEN.blit(text,text_box)
    
    #draw enigma machine
    draw(ENIGMA,PATH,SCREEN,WIDTH,HEIGHT,MARGINS,GAP,BOLD)
    
    #udate screen
    pygame.display.flip()
    #KB.draw(SCREEN,1200,200,300,500)
    
    #track user input
    for event in pygame.event.get():
        if event.type==pygame.QUIT:
            animating=False
        elif event.type==pygame.KEYDOWN:
            if event.key==pygame.K_DOWN:
                II.rotate()
            elif event.key==pygame.K_SPACE:
                INPUT=INPUT+" "
                OUTPUT=OUTPUT+" "
            else:
                key=event.unicode
                if key in "abcdefghijklmnopqrstuvwxyz":
                    letter=key.upper()
                    INPUT=INPUT+letter
                    PATH,cipher=ENIGMA.encipher(letter)
                    OUTPUT=OUTPUT+cipher
                    
        
                    
                
                    
