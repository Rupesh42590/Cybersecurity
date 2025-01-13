import pygame

def draw(ENIGMA,PATH,SCREEN,WIDTH,HEIGHT,MARGINS,GAP,BOLD):
    
    #width and height of components
    w=(WIDTH-MARGINS["left"]-MARGINS["right"]-5*GAP)/6
    h=HEIGHT-MARGINS["top"]-MARGINS["bottom"]
    
    #path coordinates
    y=[MARGINS["top"]+(signal+1)*h/27 for signal in PATH]
    #print(y)
    x=[WIDTH-MARGINS["right"]-w/2]#keyboard
    for i in [4,3,2,1,0]:#forward pass
        x.append(MARGINS["left"]+i*(w+GAP)+w*3/4)
        x.append(MARGINS["left"]+i*(w+GAP)+w*1/4)
    x.append(MARGINS["left"]+w*3/4)#recflector
    for i in [1,2,3,4]:#backward pass
        x.append(MARGINS["left"]+i*(w+GAP)+w*1/4)
        x.append(MARGINS["left"]+i*(w+GAP)+w*3/4)
    x.append(WIDTH-MARGINS["right"]-w/2)#lampboard
    
    #draw the path
    if len(PATH)>0:
        for i in range(1,21):
            if i<10:
                color="#43aa8b"
            elif i<12:
                color="#f9c74f"
            else:
                color="#e63946"
            start=(x[i-1],y[i-1])
            end=(x[i],y[i])
            pygame.draw.line(SCREEN,color,start,end,width=5)
        
    
    
    #base coordinates
    x=MARGINS["left"]
    y=MARGINS["top"]
    
    
   
    
    #enigma components
    for component in [ENIGMA.re,ENIGMA.r1,ENIGMA.r2,ENIGMA.r3,ENIGMA.pb,ENIGMA.kb]:
        
        """ENIGMA.re.draw(SCREEN,x,y,w,500,BOLD)
        ENIGMA.r1.draw(SCREEN,400,y,w,500,BOLD)
        ENIGMA.r2.draw(SCREEN,650,y,w,500,BOLD)
        ENIGMA.r3.draw(SCREEN,900,y,w,500,BOLD)
        ENIGMA.pb.draw(SCREEN,1200,y,w,500,BOLD)
        ENIGMA.kb.draw(SCREEN,1400,y,w,500,BOLD)
        """
        component.draw(SCREEN,x,y,w,500,BOLD)
        x+=w+GAP
        
    #add names
    names=["Reflector","Left","Middle","Right","Plugboard","Key/Lamb"]
    y=MARGINS["top"]*0.8
    
    for i in range(6):
        x=MARGINS["left"]+w/2+i*(w+GAP)
        title=BOLD.render(names[i],True,"white")
        text_box=title.get_rect(center=(x,y))
        SCREEN.blit(title,text_box)   

   
    