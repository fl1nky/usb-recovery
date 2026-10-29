"""Create independent small public/synthetic container samples, no USB access."""
import hashlib,io,json,struct,wave,zipfile
from pathlib import Path
from PIL import Image
root=Path(__file__).resolve().parent/'DeepRecoveryWork'
root.mkdir(exist_ok=True)
samples={}
data=io.BytesIO()
with zipfile.ZipFile(data,'w',zipfile.ZIP_DEFLATED) as z:
 z.writestr('word/document.xml','<document>Семейный рецепт</document>')
 z.writestr('[Content_Types].xml','<Types/>')
samples['.docx']=data.getvalue()
samples['.pdf']=b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF'
data=io.BytesIO();Image.new('RGB',(17,23),'blue').save(data,'WEBP');samples['.webp']=data.getvalue()
data=io.BytesIO()
with wave.open(data,'wb') as w:w.setnchannels(1);w.setsampwidth(2);w.setframerate(8000);w.writeframes(b'\x00\x00'*30)
samples['.wav']=data.getvalue()
def box(name,data):return struct.pack('>I',len(data)+8)+name.encode()+data
samples['.mp4']=box('ftyp',b'isom\0\0\0\0isom')+box('mdat',b'SYNTHETIC_NOT_DECODABLE_VIDEO')+box('moov',b'')
image=bytearray(b'\0'*(4*1024*1024-2));expected=[]
for ext,data in samples.items():
 offset=len(image);image+=data+b'\0'*31
 expected.append({'extension':ext,'offset':offset,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
image+=b'RIFF\xff\xff\xff\xffWEBP'+b'\0'*30+b'PK\3\4TRUNCATED_WITHOUT_CENTRAL_DIRECTORY'+b'\0'*1024
(root/'containers.dd').write_bytes(image)
(root/'containers-expected.json').write_text(json.dumps(expected),encoding='utf-8')
print('Synthetic deep-search fixtures generated.')
