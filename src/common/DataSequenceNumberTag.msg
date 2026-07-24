
import inet.common.INETDefs;
import inet.common.TagBase;
import inet.common.Units;

namespace inet;

class DataSequenceNumberTag extends TagBase
{
    unsigned int dataSequenceNumber;
}

// The DSS data mapping and DATA_ACK are independent fields. Keeping them in
// separate tags prevents a subflow sequence mapping from being interpreted as
// a connection-level acknowledgement.
class DataAckTag extends TagBase
{
    unsigned int dataAck;
}
