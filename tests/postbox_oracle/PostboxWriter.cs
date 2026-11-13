// SPDX-License-Identifier: AGPL-3.0-or-later
// Independent controlled writer of the schema-25 Swift wire layout.
// Uses CLR BinaryWriter, not the recovery parser. This is not a phone capture
// and does not claim to execute Telegram's Swift implementation.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

public static class PostboxWriter
{
    static void Be(BinaryWriter writer,long value,int width){for(int n=width-1;n>=0;n--)writer.Write((byte)((ulong)value>>(n*8)));}
    static void Text(BinaryWriter writer,string value){byte[] bytes=Encoding.UTF8.GetBytes(value);writer.Write(bytes.Length);writer.Write(bytes);}
    static long Peer(int ns,long id){return (long)(((ulong)id&0xffffffffUL)|((ulong)ns<<32)|(((ulong)id>>32)<<35));}
    static Dictionary<string,object> Row(int mid,int ns,uint flags,byte optional,bool author,string text,bool forwarded=false)
    {
        long peer=Peer(2,5000000000L),sender=Peer(0,77);
        int date=1740000000+Math.Abs(mid);
        byte[] key,index,value;
        using(var stream=new MemoryStream())using(var writer=new BinaryWriter(stream)){
            Be(writer,peer,8);Be(writer,ns,4);Be(writer,date,4);Be(writer,mid,4);key=stream.ToArray();
        }
        using(var stream=new MemoryStream())using(var writer=new BinaryWriter(stream)){
            writer.Write((byte)((flags&(4|256))!=0?2:0));writer.Write(date);index=stream.ToArray();
        }
        using(var stream=new MemoryStream())using(var writer=new BinaryWriter(stream)){
            writer.Write((byte)0);writer.Write((uint)(1000+Math.Abs(mid)));writer.Write((uint)2);writer.Write(optional);
            if((optional&1)!=0)writer.Write((long)7123123);
            if((optional&2)!=0)writer.Write((uint)55);
            if((optional&4)!=0)writer.Write((long)7123124);
            if((optional&8)!=0)writer.Write((uint)731);
            if((optional&16)!=0)writer.Write((uint)73);
            if((optional&32)!=0)writer.Write((long)456);
            writer.Write(flags);writer.Write((uint)16);
            writer.Write((byte)(forwarded?63:0));
            if(forwarded){writer.Write(Peer(1,88));writer.Write(date-12);writer.Write(Peer(2,99));writer.Write(peer);writer.Write(0);writer.Write(4);Text(writer,"FORWARD_SIGNATURE_NEVER_MESSAGE");Text(writer,"PSA_NEVER_MESSAGE");writer.Write(1);}
            writer.Write((byte)(author?1:0));if(author)writer.Write(sender);
            Text(writer,text);
            writer.Write(2);Text(writer,"ATTRIBUTE_NEVER_MESSAGE");Text(writer,"<script>OPAQUE_NEVER_MESSAGE</script>");
            writer.Write(1);Text(writer,"MEDIA_URL_NEVER_FETCH https://invalid.example/image.jpg");
            writer.Write(1);writer.Write(5);writer.Write((long)7382838123);
            value=stream.ToArray();
        }
        return new Dictionary<string,object>{{"key",Convert.ToBase64String(key)},{"index",Convert.ToBase64String(index)},
            {"value",Convert.ToBase64String(value)},{"text",text},{"peer","ios-peer:"+((ulong)peer).ToString("x16")},
            {"sender",author?"ios-peer:"+((ulong)sender).ToString("x16"):null},{"namespace",ns},{"mid",mid},{"date",date},{"unsent",(flags&(1|2|32))!=0}};
    }
    public static int Main(string[] args)
    {
        if(args.Length!=1||File.Exists(args[0]))return 2;
        var rows=new List<Dictionary<string,object>>{
            Row(5,0,4,0,true,"Бабушка: рецепт пирожков 🥧\n第二行 <img src=x onerror=alert(1)>"),
            Row(5,1,4,63,false,"Бабушка: рецепт пирожков 🥧\n第二行 <img src=x onerror=alert(1)>",true),
            Row(-7,3,33,32,true,"Unsent local Postbox text"),
            Row(8,0,256,1,true,"Long Postbox "+new string('Я',60000)),
            Row(9,0,4,0,false,"")};
        File.WriteAllText(args[0],new JavaScriptSerializer{MaxJsonLength=4000000}.Serialize(rows),new UTF8Encoding(false));
        return 0;
    }
}
