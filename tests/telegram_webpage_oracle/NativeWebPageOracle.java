import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import org.telegram.tgnet.*;
import org.telegram.messenger.ApplicationLoader;

// Input-only native serializers. Controlled values, no product decoder.
public final class NativeWebPageOracle {
    static TLRPC.TL_peerUser peer(long id) {
        TLRPC.TL_peerUser p = new TLRPC.TL_peerUser(); p.user_id = id; return p;
    }
    static TLRPC.WebPage page(int index) {
        TLRPC.WebPage page;
        switch(index) {
            case 0: page = new TLRPC.TL_webPageEmpty(); page.flags = 1; break;
            case 1: page = new TLRPC.TL_webPagePending(); page.flags = 1; page.date = 1794009000; break;
            case 2: page = new TLRPC.TL_webPageEmpty_layer165(); break;
            case 3: page = new TLRPC.TL_webPagePending_layer165(); page.date = 1794009000; break;
            case 4: page = new TLRPC.TL_webPageUrlPending(); break;
            case 5: case 6:
                page = new TLRPC.TL_webPage();
                page.flags = 15 | 32 | 64 | 128 | 256;
                page.has_large_media = true; page.video_cover_photo = true;
                if(index == 6) {
                    page.flags |= 16;
                    TLRPC.TL_photoEmpty photo = new TLRPC.TL_photoEmpty(); photo.id = 404; page.photo = photo;
                }
                break;
            default:
                page = new TLRPC.TL_webPage_layer107(); page.flags = 15 | 32 | 64 | 128 | 256; break;
        }
        page.id = -900 - index;
        page.url = "https://example.invalid/NEVER_FETCH_" + index;
        page.display_url = "example.invalid";
        page.hash = -300;
        page.type = "article"; page.site_name = "Untrusted site";
        page.title = "<script>NEVER_EXECUTE</script>";
        page.description = "Preview text is not message text";
        page.embed_url = "file:///NEVER_OPEN"; page.embed_type = "text/html";
        page.embed_width = 320; page.embed_height = 240; page.duration = 12;
        page.author = "PAGE_AUTHOR_IS_NOT_SENDER";
        return page;
    }
    public static void main(String[] args) throws Exception {
        Path out = Path.of(args[0]); Files.createDirectories(out);
        for (int i=0; i<8; i++) {
            TLRPC.TL_message message = new TLRPC.TL_message();
            message.flags = 256 | 512; message.id = 7301+i; message.date = 1794001000+i;
            message.from_id = peer(77); message.peer_id = peer(77);
            message.message = i == 1 ? "" : "Recipe \u043f\u0438\u0440\u043e\u0433 \ud83e\udd67\nlink variant " + i;
            message.attachPath = "../../NEVER_OPEN_NATIVE_WEBPAGE.bin";
            TLRPC.TL_messageMediaWebPage media = i == 2 || i == 3
                ? new TLRPC.TL_messageMediaWebPage_layer165() : new TLRPC.TL_messageMediaWebPage();
            media.flags = 27; media.force_large_media=true; media.force_small_media=true; media.manual=true; media.safe=true;
            media.webpage = page(i); message.media = media;
            ApplicationLoader.testEnvironment = false;
            SerializedData stream = new SerializedData(); message.serializeToStream(stream);
            Files.write(out.resolve("message-"+i+".blob"), stream.toByteArray(), StandardOpenOption.CREATE_NEW);
            Files.writeString(out.resolve("message-"+i+".text"), message.message, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        }
        System.out.println("8 official Java WebPage messages serialized");
    }
}
