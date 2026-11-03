import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import org.telegram.tgnet.*;
import org.telegram.messenger.ApplicationLoader;

// Controlled values, pinned official TL writer and Android attachment-tail writer.
// No production recovery parser is imported or executed by this producer.
public final class NativeScheduledOracle {
    static TLRPC.TL_peerUser peer(long id) {
        TLRPC.TL_peerUser p = new TLRPC.TL_peerUser(); p.user_id = id; return p;
    }
    public static void main(String[] args) throws Exception {
        Path output = Path.of(args[0]); Files.createDirectories(output);
        for (int i = 0; i < 3; ++i) {
            TLRPC.TL_message m = new TLRPC.TL_message();
            m.flags = 256; m.out = true; m.id = 5101 + i; m.date = 1794001000 + i;
            m.from_id = peer(77); m.peer_id = peer(909);
            m.message = i == 0 ? "Scheduled native \u043f\u0438\u0440\u043e\u0433 \ud83e\udd67\n\u7b2c\u4e8c\u884c" : i == 1 ? "Scheduled alternate text" : "";
            m.attachPath = "../../FILENAME_NEVER_OPEN_SCHEDULED.bin";
            if (i == 2) {
                m.flags |= 512;
                TLRPC.TL_messageMediaDocument media = new TLRPC.TL_messageMediaDocument();
                media.flags = 1;
                TLRPC.TL_documentEmpty document = new TLRPC.TL_documentEmpty(); document.id = 0;
                media.document = document; m.media = media;
            }
            ApplicationLoader.testEnvironment = false;
            SerializedData writer = new SerializedData(); m.serializeToStream(writer);
            byte[] raw = writer.toByteArray();
            Files.write(output.resolve("scheduled-" + i + ".blob"), raw, StandardOpenOption.CREATE_NEW);
            Files.writeString(output.resolve("scheduled-" + i + ".text"), m.message, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        }
        System.out.println("3 native Java TL serializers completed");
    }
}
