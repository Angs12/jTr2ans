from transformers import BertTokenizer, BertModel
import pickle
import os
import torch
import numpy as np
from tqdm import tqdm
from data import load_paired_data_fast
import argparse
import logging
import sys

def get_logger(name):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename=name)
    logger = logging.getLogger(__name__)
    s_handle = logging.StreamHandler(sys.stdout)
    s_handle.setLevel(logging.INFO)
    s_handle.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s[:%(lineno)d] - %(message)s"))
    logger.addHandler(s_handle)
    return logger

class BinBertModel(BertModel):
    def __init__(self, config, add_pooling_layer=True):
        super().__init__(config)
        self.config = config
        self.embeddings.position_embeddings=self.embeddings.word_embeddings
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="jTrans-EvalSave")
    parser.add_argument("--model_path", type=str, default='./models/jTrans-finetune', help="Path to the model")
    parser.add_argument("--dataset_path", type=str, default='./BinaryCorp/small_test', help="Path to the dataset")
    parser.add_argument("--experiment_path", type=str, default='./experiments/BinaryCorp-3M/jTrans.pkl', help="Path to the experiment")
    parser.add_argument("--tokenizer", type=str, default='./jtrans_tokenizer/')
    parser.add_argument("--batch_size", type=int, default=256, help="Batch size for embedding generation")
    parser.add_argument("--limit", type=int, default=None, help="Max projects to process")

    args = parser.parse_args()

    from datetime import datetime
    now = datetime.now() # current date and time
    TIMESTAMP="%Y%m%d%H%M"
    tim = now.strftime(TIMESTAMP)
    safe_name = f"jTrans-eval-{os.path.basename(args.dataset_path)}_{tim}"
    logger = get_logger(safe_name)
    logger.info(f"Loading Pretrained Model from {args.model_path} ...")
    model = BinBertModel.from_pretrained(args.model_path)

    model.eval()
    device = torch.device("cuda")
    model.to(device)

    logger.info("Done ...")
    tokenizer = BertTokenizer.from_pretrained(args.tokenizer)
    logger.info("Tokenizer Done ...")
   
    logger.info("Preparing Datasets ...")
    datas, ebds = load_paired_data_fast(args.dataset_path, add_ebd=True, limit=args.limit)

    # Phase 1: collect all function strings with lookup table
    texts, lookup = [], []
    for i in range(len(datas)):
        pairs = datas[i]
        for j in ['O0','O1','O2','O3','Os']:
            if ebds[i].get(j) is not None:
                texts.append(pairs[ebds[i][j]])
                lookup.append((i, j))

    # Phase 2: batch tokenize + infer
    logger.info(f"Generating embeddings for {len(texts)} functions, batch_size={args.batch_size} ...")
    embs = []
    with torch.no_grad():
        for start in tqdm(range(0, len(texts), args.batch_size)):
            batch = texts[start:start + args.batch_size]
            ret = tokenizer(batch, add_special_tokens=True, max_length=512,
                            padding='max_length', truncation=True, return_tensors='pt')
            out = model(input_ids=ret['input_ids'].cuda(),
                        attention_mask=ret['attention_mask'].cuda())
            embs.append(out.pooler_output.detach().cpu())

    # Phase 3: write back into ebds
    embs = torch.cat(embs)
    for idx, (i, j) in enumerate(lookup):
        ebds[i][j] = embs[idx]

    logger.info("ebds start writing")
    fi=open(args.experiment_path,'wb')
    pickle.dump(ebds,fi)
    fi.close()

