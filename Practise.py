email = "mahlon.k.kirwa@army.mil"
temp1 = email.replace('@',".")
temp2 = temp1.replace('.',',')
lst = temp2.split(",")
print(lst)