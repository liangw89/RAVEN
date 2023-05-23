from sklearn.metrics import roc_auc_score, auc,precision_recall_curve

def ow_pr_curve_evaluation(model, mon_samples, unmon_samples, unmon_label):
	"""
	Using sklearn to compute the PR curve data
	"""   
	y_prob = []
	y_test = []
	for s in range(mon_samples.shape[0]):
		test_example = mon_samples[s]
		predict_prob = model.predict(np.array([test_example]))
		# print (predict_prob)
		prob = max(list(predict_prob[0])[:-1])     
		y_prob.append(prob)
		y_test.append(1)
	
	
	for s in range(unmon_samples.shape[0]):
		test_example = unmon_samples[s]
		predict_prob = model.predict(np.array([test_example]))
		prob = max(list(predict_prob[0])[:-1])
		y_prob.append(prob)
		y_test.append(0)

	precision, recall, thresholds = precision_recall_curve(y_test, y_prob)
	
	print ("Average PR-AUC score", auc(recall, precision))
	print ("Average ROC-AUC score", roc_auc_score(y_test, y_prob))
	res = []
	for i in zip(recall, precision):
		 res.append((i[0], i[1]))
	return res


def ow_evaluation_rprecision(model, mon_samples, unmon_samples, mon_labels, unmon_label):
	"""
	Compute r-precision
	"""  

	r = 5 # The ratio in r-precision
	res = []
	TP, FP, WP, P, N = 0, 0, 0, 0, 0 # WP: wrong positive
	TN, FN = 0, 0

	predicts = model.predict_classes(mon_samples)
	P = len(predicts)
	for i in range(len(predicts)):
		if predicts[i] != unmon_label:
			if predicts[i] == mon_labels[i]:
				TP = TP + 1
			else:
				WP = WP + 1
		else:
			FN = FN + 1

	predicts = model.predict_classes(unmon_samples)
	N = len(predicts)
	for i in range(len(predicts)):
		if predicts[i] != unmon_label:
			FP = FP + 1
		else:
			TN = TN + 1
	try:
		res = [TP, WP, FP, TN, FN, float(TP*N)/(TP*N + WP*N + r*P*FP ), float(TP)/(TP+FN)]
	except Exception as e:
		res = [TP, WP, FP, TN, FN, 0, 0]
	return res